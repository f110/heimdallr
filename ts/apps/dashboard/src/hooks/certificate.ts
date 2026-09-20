import { createConnectQueryKey, useMutation, useQuery } from '@connectrpc/connect-query'
import { useQueryClient } from '@tanstack/react-query'

import { CertificateService } from '../connect/dashboard_pb'

export function useListCertificates() {
  return useQuery(CertificateService.method.listCertificates, {})
}

export function useListAgents() {
  return useQuery(CertificateService.method.listAgents, {})
}

export function useListAgentBackends() {
  return useQuery(CertificateService.method.listAgentBackends, {})
}

export function useNewClientCertificate() {
  const invalidate = useInvalidateCertificates()

  return useMutation(CertificateService.method.newClientCertificate, { onSuccess: invalidate })
}

export function useRevokeCertificate() {
  const invalidate = useInvalidateCertificates()

  return useMutation(CertificateService.method.revokeCertificate, { onSuccess: invalidate })
}

export function useRegisterAgent() {
  const invalidate = useInvalidateCertificates()

  return useMutation(CertificateService.method.registerAgent, { onSuccess: invalidate })
}

// Both lists are built from the same certificates on the server, so every change invalidates both.
function useInvalidateCertificates() {
  const queryClient = useQueryClient()

  return () => {
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({
        schema: CertificateService.method.listCertificates,
        cardinality: 'finite',
      }),
    })
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({
        schema: CertificateService.method.listAgents,
        cardinality: 'finite',
      }),
    })
  }
}
