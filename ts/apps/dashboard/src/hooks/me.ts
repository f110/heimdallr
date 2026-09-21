import { createConnectQueryKey, useMutation, useQuery } from '@connectrpc/connect-query'
import { useQueryClient } from '@tanstack/react-query'

import { MeService } from '../connect/dashboard_pb'

export function useGetMe() {
  return useQuery(MeService.method.getMe, {})
}

export function useAddDevice() {
  const queryClient = useQueryClient()

  return useMutation(MeService.method.addDevice, {
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({ schema: MeService.method.getMe, cardinality: 'finite' }),
      })
    },
  })
}
