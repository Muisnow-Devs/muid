package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	idclaims "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/enttest"
	"sanzi.io/muid/internal/profile/ent/useravatar"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/internal/profile/synthavatar"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/storage"
	"sanzi.io/muid/pkg/shared/topics"
)

// fakePubSub records published messages.
type fakePubSub struct {
	mu       sync.Mutex
	messages map[topics.Topic][][]byte
}

func newFakePubSub() *fakePubSub {
	return &fakePubSub{messages: make(map[topics.Topic][][]byte)}
}

func (f *fakePubSub) Publish(topic topics.Topic, message []byte) error {
	return f.PublishWithOptions(topic, message, pubsub.PublishOptions{})
}

func (f *fakePubSub) PublishWithOptions(
	topic topics.Topic,
	message []byte,
	_ pubsub.PublishOptions,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages[topic] = append(f.messages[topic], message)
	return nil
}

func (f *fakePubSub) PublishWithContext(
	_ context.Context,
	topic topics.Topic,
	message []byte,
	opts pubsub.PublishOptions,
) error {
	return f.PublishWithOptions(topic, message, opts)
}

func (f *fakePubSub) Subscribe(
	_ context.Context,
	_ topics.Topic,
	_ pubsub.SubscribeOptions,
	_ func(context.Context, []byte) error,
) error {
	return nil
}

func (f *fakePubSub) profileEvents(t *testing.T) []*profileevent.ProfileChangedEvent {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*profileevent.ProfileChangedEvent
	for _, payload := range f.messages[topics.TopicProfileChange] {
		ev := &profileevent.ProfileChangedEvent{}
		if err := proto.Unmarshal(payload, ev); err != nil {
			t.Fatalf("unmarshal published event: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

// waitForProfileEvents polls for asynchronously published events.
func (f *fakePubSub) waitForProfileEvents(
	t *testing.T,
	n int,
) []*profileevent.ProfileChangedEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		evs := f.profileEvents(t)
		if len(evs) >= n {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d events, have %d", n, len(evs))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fakeObjectStore is an in-memory storage.ObjectStore.
type fakeObjectStore struct {
	mu      sync.Mutex
	objects map[string][]byte // bucket + "/" + key
	types   map[string]string
}

func newFakeObjectStore() *fakeObjectStore {
	return &fakeObjectStore{
		objects: make(map[string][]byte),
		types:   make(map[string]string),
	}
}

func (s *fakeObjectStore) put(bucket, key string, body []byte, contentType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[bucket+"/"+key] = body
	s.types[bucket+"/"+key] = contentType
}

func (s *fakeObjectStore) has(bucket, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.objects[bucket+"/"+key]
	return ok
}

func (s *fakeObjectStore) PresignPut(
	_ context.Context,
	_, _, _ string,
	exp time.Duration,
) (string, time.Time, error) {
	return "https://upload.example/presigned", time.Now().Add(exp), nil
}

func (s *fakeObjectStore) HeadObject(
	_ context.Context,
	bucket, objectKey string,
) (storage.ObjectHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, ok := s.objects[bucket+"/"+objectKey]
	if !ok {
		return storage.ObjectHead{}, storage.ErrObjectNotFound
	}
	return storage.ObjectHead{
		Size:        int64(len(body)),
		ContentType: s.types[bucket+"/"+objectKey],
	}, nil
}

func (s *fakeObjectStore) GetObject(
	ctx context.Context,
	bucket, objectKey string,
) (io.ReadCloser, storage.ObjectHead, error) {
	head, err := s.HeadObject(ctx, bucket, objectKey)
	if err != nil {
		return nil, storage.ObjectHead{}, err
	}
	s.mu.Lock()
	body := s.objects[bucket+"/"+objectKey]
	s.mu.Unlock()
	return io.NopCloser(bytes.NewReader(body)), head, nil
}

func (s *fakeObjectStore) PutObject(
	_ context.Context,
	bucket, objectKey string,
	body []byte,
	contentType string,
) error {
	s.put(bucket, objectKey, body, contentType)
	return nil
}

func (s *fakeObjectStore) DeleteObject(_ context.Context, bucket, objectKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, bucket+"/"+objectKey)
	delete(s.types, bucket+"/"+objectKey)
	return nil
}

// newTestManager spins up a Manager on an in-memory sqlite database with a
// fake object store and pubsub.
func newTestManager(
	t *testing.T,
	name string,
) (*Manager, *ent.Client, *fakePubSub, *fakeObjectStore) {
	t.Helper()

	client := enttest.Open(t, "sqlite3", "file:"+name+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })

	ps := newFakePubSub()
	store := newFakeObjectStore()
	m := NewManager(ManagerConfig{
		DB:     client,
		PubSub: ps,
		Media: &AvatarMedia{
			Store:          store,
			UploadBucket:   "staging",
			AssetsBucket:   "assets",
			PublicAssetURL: "https://cdn.example",
		},
		Proc: media.NewWebPRasterAvatarProcessor(),
	})
	return m, client, ps, store
}

func mustCreateProfile(t *testing.T, m *Manager) uuid.UUID {
	t.Helper()
	id, err := m.CreateProfile(context.Background(), nil)
	if err != nil {
		t.Fatalf("CreateProfile() error = %v", err)
	}
	return id
}

func TestCreateProfileDefaults(t *testing.T) {
	t.Parallel()
	m, client, _, _ := newTestManager(t, "createdefaults")
	ctx := context.Background()

	id := mustCreateProfile(t, m)

	p, err := client.UserProfile.Get(ctx, id)
	if err != nil {
		t.Fatalf("load created profile: %v", err)
	}
	if p.Locale != "en" {
		t.Errorf("Locale = %q, want en", p.Locale)
	}
	if p.Timezone != "UTC" {
		t.Errorf("Timezone = %q, want UTC", p.Timezone)
	}
	if p.Username == "" || p.DisplayName == "" {
		t.Errorf("Username/DisplayName empty: %q %q", p.Username, p.DisplayName)
	}
}

func TestCreateProfileFromIdentityClaims(t *testing.T) {
	t.Parallel()
	m, client, _, _ := newTestManager(t, "createclaims")
	ctx := context.Background()

	idn := &idclaims.IdentityInformation{}
	idn.SetName("Ada Lovelace")
	idn.SetLocale("zh-TW")
	idn.SetTimezone("Asia/Taipei")

	id, err := m.CreateProfile(ctx, idn)
	if err != nil {
		t.Fatalf("CreateProfile() error = %v", err)
	}

	p, err := client.UserProfile.Get(ctx, id)
	if err != nil {
		t.Fatalf("load created profile: %v", err)
	}
	if p.DisplayName != "Ada Lovelace" {
		t.Errorf("DisplayName = %q", p.DisplayName)
	}
	if p.Locale != "zh-TW" || p.Timezone != "Asia/Taipei" {
		t.Errorf("Locale/Timezone = %q/%q", p.Locale, p.Timezone)
	}
}

func TestCreateProfileRowCandidateCollision(t *testing.T) {
	t.Parallel()
	m, client, _, _ := newTestManager(t, "createcollision")
	ctx := context.Background()

	taken := "user_aaaaaaa1"
	free := "user_aaaaaaa2"
	if _, err := client.UserProfile.Create().
		SetLocale("en").SetTimezone("UTC").
		SetDisplayName("x").SetUsername(taken).
		Save(ctx); err != nil {
		t.Fatalf("seed taken username: %v", err)
	}

	tx, err := m.db.Tx(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	user, err := createProfileRow(ctx, tx, []string{taken, free}, "name", "en", "UTC")
	if err != nil {
		t.Fatalf("createProfileRow() error = %v", err)
	}
	if user.Username != free {
		t.Errorf("Username = %q, want %q (next free candidate)", user.Username, free)
	}
}

func TestCreateProfileRowExhausted(t *testing.T) {
	t.Parallel()
	m, client, _, _ := newTestManager(t, "createexhausted")
	ctx := context.Background()

	taken := []string{"user_bbbbbbb1", "user_bbbbbbb2"}
	for _, u := range taken {
		if _, err := client.UserProfile.Create().
			SetLocale("en").SetTimezone("UTC").
			SetDisplayName("x").SetUsername(u).
			Save(ctx); err != nil {
			t.Fatalf("seed taken username: %v", err)
		}
	}

	tx, err := m.db.Tx(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	_, err = createProfileRow(ctx, tx, taken, "name", "en", "UTC")
	if !errors.Is(err, ErrUsernameExhausted) {
		t.Fatalf("error = %v, want ErrUsernameExhausted", err)
	}
}

func TestGetProfileNotFound(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, "getnotfound")

	_, err := m.GetProfile(context.Background(), uuid.New())
	if !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("error = %v, want ErrProfileNotFound", err)
	}
}

func TestGetProfileSynthAvatarFallback(t *testing.T) {
	t.Parallel()
	m, _, _, _ := newTestManager(t, "getsynth")
	ctx := context.Background()

	id := mustCreateProfile(t, m)

	p, err := m.GetProfile(ctx, id)
	if err != nil {
		t.Fatalf("GetProfile() error = %v", err)
	}
	wantURL, err := synthavatar.DataURL(id)
	if err != nil {
		t.Fatal(err)
	}
	if p.AvatarURL != wantURL {
		t.Errorf("AvatarURL is not the synthetic fallback data URL")
	}
	if p.AvatarObjectKey != "" {
		t.Errorf("AvatarObjectKey = %q, want empty", p.AvatarObjectKey)
	}
}

func TestGetProfileDisplayAvatarSelection(t *testing.T) {
	t.Parallel()
	m, client, _, _ := newTestManager(t, "getdisplay")
	ctx := context.Background()

	id := mustCreateProfile(t, m)
	now := time.Now()

	// Older committed, newer committed, and a pending row; UUIDv7 ids order them.
	for _, row := range []struct {
		key      string
		uploaded bool
	}{
		{"avatars/" + id.String() + "/old.webp", true},
		{"avatars/" + id.String() + "/new.webp", true},
		{"avatars/" + id.String() + "/pending", false},
	} {
		create := client.UserAvatar.Create().
			SetID(shared.UUIDV7()).
			SetUserID(id).
			SetObjectKey(row.key).
			SetContentType("image/webp").
			SetByteSize(1)
		if row.uploaded {
			create = create.SetUploadedAt(now)
		}
		if _, err := create.Save(ctx); err != nil {
			t.Fatalf("seed avatar row: %v", err)
		}
	}

	p, err := m.GetProfile(ctx, id)
	if err != nil {
		t.Fatalf("GetProfile() error = %v", err)
	}
	wantKey := "avatars/" + id.String() + "/new.webp"
	if p.AvatarObjectKey != wantKey {
		t.Errorf("AvatarObjectKey = %q, want %q (latest committed)", p.AvatarObjectKey, wantKey)
	}
	if p.AvatarURL != "https://cdn.example/"+wantKey {
		t.Errorf("AvatarURL = %q", p.AvatarURL)
	}
}

func TestUpdateProfile(t *testing.T) {
	t.Parallel()
	m, client, ps, _ := newTestManager(t, "update")
	ctx := context.Background()

	id := mustCreateProfile(t, m)

	idn := &idclaims.IdentityInformation{}
	idn.SetUsername("ada.l")
	idn.SetBio(" pioneer ")
	mask := &fieldmaskpb.FieldMask{Paths: []string{"identity.username", "identity.bio"}}

	if err := m.UpdateProfile(ctx, id, mask, idn); err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}

	p, err := client.UserProfile.Get(ctx, id)
	if err != nil {
		t.Fatalf("reload profile: %v", err)
	}
	if p.Username != "ada.l" || p.Biography != "pioneer" {
		t.Errorf("Username/Biography = %q/%q", p.Username, p.Biography)
	}

	evs := ps.profileEvents(t)
	if len(evs) != 1 {
		t.Fatalf("published events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.GetUserId() != id.String() {
		t.Errorf("event user_id = %q", ev.GetUserId())
	}
	paths := ev.GetChangedFields().GetPaths()
	if len(paths) != 2 || paths[0] != "bio" || paths[1] != "username" {
		t.Errorf("changed_fields = %v, want [bio username]", paths)
	}
	if ev.GetChanges().GetUsername() != "ada.l" || ev.GetChanges().GetBio() != "pioneer" {
		t.Errorf("claims = %v", ev.GetChanges())
	}
}

func TestUpdateProfileErrors(t *testing.T) {
	t.Parallel()
	m, client, _, _ := newTestManager(t, "updateerrors")
	ctx := context.Background()

	id := mustCreateProfile(t, m)

	t.Run("profile not found", func(t *testing.T) {
		idn := &idclaims.IdentityInformation{}
		idn.SetBio("x")
		err := m.UpdateProfile(ctx, uuid.New(),
			&fieldmaskpb.FieldMask{Paths: []string{"identity.bio"}}, idn)
		if !errors.Is(err, ErrProfileNotFound) {
			t.Fatalf("error = %v, want ErrProfileNotFound", err)
		}
	})

	t.Run("username conflict", func(t *testing.T) {
		if _, err := client.UserProfile.Create().
			SetLocale("en").SetTimezone("UTC").
			SetDisplayName("x").SetUsername("takenname").
			Save(ctx); err != nil {
			t.Fatalf("seed conflicting username: %v", err)
		}
		idn := &idclaims.IdentityInformation{}
		idn.SetUsername("takenname")
		err := m.UpdateProfile(ctx, id,
			&fieldmaskpb.FieldMask{Paths: []string{"identity.username"}}, idn)
		if !errors.Is(err, ErrUpdateConflict) {
			t.Fatalf("error = %v, want ErrUpdateConflict", err)
		}
	})

	t.Run("unsupported path", func(t *testing.T) {
		err := m.UpdateProfile(ctx, id,
			&fieldmaskpb.FieldMask{Paths: []string{"identity.email"}}, nil)
		if !errors.Is(err, ErrUnsupportedMaskPath) {
			t.Fatalf("error = %v, want ErrUnsupportedMaskPath", err)
		}
	})

	t.Run("invalid value rolls back", func(t *testing.T) {
		idn := &idclaims.IdentityInformation{}
		idn.SetUsername("_bad")
		err := m.UpdateProfile(ctx, id,
			&fieldmaskpb.FieldMask{Paths: []string{"identity.username"}}, idn)
		var ia InvalidArgumentError
		if !errors.As(err, &ia) {
			t.Fatalf("error = %v, want InvalidArgumentError", err)
		}
	})
}

func TestStartAvatarUploadReplacesPending(t *testing.T) {
	t.Parallel()
	m, client, _, store := newTestManager(t, "startavatar")
	ctx := context.Background()

	id := mustCreateProfile(t, m)

	first, err := m.StartAvatarUpload(ctx, id, "image/png")
	if err != nil {
		t.Fatalf("first StartAvatarUpload() error = %v", err)
	}
	// Simulate the client having uploaded to the first staging key.
	store.put("staging", first.ObjectKey, []byte("x"), "image/png")

	second, err := m.StartAvatarUpload(ctx, id, "image/png")
	if err != nil {
		t.Fatalf("second StartAvatarUpload() error = %v", err)
	}
	if second.ObjectKey == first.ObjectKey {
		t.Fatal("second session reused the first object key")
	}

	pending, err := client.UserAvatar.Query().
		Where(
			useravatar.HasUserWith(userprofile.ID(id)),
			useravatar.UploadedAtIsNil(),
		).
		All(ctx)
	if err != nil {
		t.Fatalf("query pending rows: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending rows = %d, want 1 (stale session replaced)", len(pending))
	}
	if pending[0].ObjectKey != second.ObjectKey {
		t.Errorf("pending row key = %q, want %q", pending[0].ObjectKey, second.ObjectKey)
	}
}

func TestStartAvatarUploadErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("not configured", func(t *testing.T) {
		t.Parallel()
		mNo, _, _, _ := newTestManager(t, "startnoconf")
		mNo.media = nil
		_, err := mNo.StartAvatarUpload(ctx, uuid.New(), "image/png")
		if !errors.Is(err, ErrAvatarNotConfigured) {
			t.Fatalf("error = %v, want ErrAvatarNotConfigured", err)
		}
	})

	t.Run("profile not found", func(t *testing.T) {
		t.Parallel()
		m, _, _, _ := newTestManager(t, "startnoprofile")
		_, err := m.StartAvatarUpload(ctx, uuid.New(), "image/png")
		if !errors.Is(err, ErrProfileNotFound) {
			t.Fatalf("error = %v, want ErrProfileNotFound", err)
		}
	})

	t.Run("bad content type", func(t *testing.T) {
		t.Parallel()
		m, _, _, _ := newTestManager(t, "startbadct")
		id := mustCreateProfile(t, m)
		_, err := m.StartAvatarUpload(ctx, id, "text/plain")
		var ia InvalidArgumentError
		if !errors.As(err, &ia) {
			t.Fatalf("error = %v, want InvalidArgumentError", err)
		}
	})
}

func TestCompleteAvatarUpload(t *testing.T) {
	t.Parallel()
	m, client, ps, store := newTestManager(t, "completeavatar")
	ctx := context.Background()

	id := mustCreateProfile(t, m)

	sess, err := m.StartAvatarUpload(ctx, id, "image/png")
	if err != nil {
		t.Fatalf("StartAvatarUpload() error = %v", err)
	}

	// Stage a real PNG as the client upload.
	png, err := synthavatar.PNGBytes(id)
	if err != nil {
		t.Fatal(err)
	}
	store.put("staging", sess.ObjectKey, png, "image/png")

	publicURL, err := m.CompleteAvatarUpload(ctx, id, sess.ObjectKey, int64(len(png)))
	if err != nil {
		t.Fatalf("CompleteAvatarUpload() error = %v", err)
	}
	if publicURL == "" {
		t.Fatal("empty public URL")
	}

	committed, err := client.UserAvatar.Query().
		Where(
			useravatar.HasUserWith(userprofile.ID(id)),
			useravatar.UploadedAtNotNil(),
		).
		All(ctx)
	if err != nil {
		t.Fatalf("query committed rows: %v", err)
	}
	if len(committed) != 1 {
		t.Fatalf("committed rows = %d, want 1", len(committed))
	}
	if !store.has("assets", committed[0].ObjectKey) {
		t.Error("processed WebP missing from assets bucket")
	}

	pendingCount, err := client.UserAvatar.Query().
		Where(
			useravatar.HasUserWith(userprofile.ID(id)),
			useravatar.UploadedAtIsNil(),
		).
		Count(ctx)
	if err != nil {
		t.Fatalf("count pending rows: %v", err)
	}
	if pendingCount != 0 {
		t.Errorf("pending rows = %d, want 0 (consumed by completion)", pendingCount)
	}

	evs := ps.waitForProfileEvents(t, 1)
	paths := evs[0].GetChangedFields().GetPaths()
	if len(paths) != 2 || paths[0] != "avatar_object_key" || paths[1] != "avatar_url" {
		t.Errorf("changed_fields = %v", paths)
	}
	if evs[0].GetChanges().GetPicture() != publicURL {
		t.Errorf("claims picture = %q, want %q", evs[0].GetChanges().GetPicture(), publicURL)
	}

	t.Run("second completion rejected", func(t *testing.T) {
		_, err := m.CompleteAvatarUpload(ctx, id, sess.ObjectKey, int64(len(png)))
		if !errors.Is(err, ErrAvatarSessionNotFound) {
			t.Fatalf("error = %v, want ErrAvatarSessionNotFound (pending row consumed)", err)
		}
	})
}

func TestCompleteAvatarUploadErrors(t *testing.T) {
	t.Parallel()
	m, _, _, store := newTestManager(t, "completeerrors")
	ctx := context.Background()

	id := mustCreateProfile(t, m)

	t.Run("foreign object key", func(t *testing.T) {
		_, err := m.CompleteAvatarUpload(ctx, id, "avatars/other-user/key", 1)
		if !errors.Is(err, ErrObjectKeyNotOwned) {
			t.Fatalf("error = %v, want ErrObjectKeyNotOwned", err)
		}
	})

	t.Run("unknown session", func(t *testing.T) {
		_, err := m.CompleteAvatarUpload(ctx, id, "avatars/"+id.String()+"/nosuch", 1)
		if !errors.Is(err, ErrAvatarSessionNotFound) {
			t.Fatalf("error = %v, want ErrAvatarSessionNotFound", err)
		}
	})

	t.Run("staging object missing", func(t *testing.T) {
		sess, err := m.StartAvatarUpload(ctx, id, "image/png")
		if err != nil {
			t.Fatalf("StartAvatarUpload() error = %v", err)
		}
		_, err = m.CompleteAvatarUpload(ctx, id, sess.ObjectKey, 1)
		if !errors.Is(err, ErrAvatarObjectMissing) {
			t.Fatalf("error = %v, want ErrAvatarObjectMissing", err)
		}
	})

	t.Run("byte size mismatch", func(t *testing.T) {
		sess, err := m.StartAvatarUpload(ctx, id, "image/png")
		if err != nil {
			t.Fatalf("StartAvatarUpload() error = %v", err)
		}
		store.put("staging", sess.ObjectKey, []byte("1234"), "image/png")
		_, err = m.CompleteAvatarUpload(ctx, id, sess.ObjectKey, 99)
		var ia InvalidArgumentError
		if !errors.As(err, &ia) {
			t.Fatalf("error = %v, want InvalidArgumentError", err)
		}
	})

	t.Run("invalid image", func(t *testing.T) {
		sess, err := m.StartAvatarUpload(ctx, id, "image/png")
		if err != nil {
			t.Fatalf("StartAvatarUpload() error = %v", err)
		}
		body := []byte("this is not a png")
		store.put("staging", sess.ObjectKey, body, "image/png")
		_, err = m.CompleteAvatarUpload(ctx, id, sess.ObjectKey, int64(len(body)))
		if !errors.Is(err, ErrInvalidAvatarImage) {
			t.Fatalf("error = %v, want ErrInvalidAvatarImage", err)
		}
	})
}
