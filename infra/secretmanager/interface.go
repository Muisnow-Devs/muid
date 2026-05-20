// Package secretmanager provides Google Secret Manager implementations of the shared contract.
package secretmanager

import gsm "sanzi.io/muid/pkg/shared/secretmanager"

// SecretManager is the contract implemented by [NewGCPSecretManager] and [NewFakeSecretManager].
type SecretManager = gsm.SecretManager
