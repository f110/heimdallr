package proxyv1alpha2

func (in *BackendStatus) IsConfigured(ownerAndRepo string) bool {
	for _, v := range in.WebhookConfigurations {
		if v.Repository == ownerAndRepo {
			return true
		}
	}

	return false
}
