import { createConnectQueryKey, useMutation, useQuery } from '@connectrpc/connect-query'
import { useQueryClient } from '@tanstack/react-query'

import { AdminService } from '../connect/dashboard_pb'

export function useListUsers() {
  return useQuery(AdminService.method.listUsers, {})
}

export function useGetUser(id: string) {
  return useQuery(AdminService.method.getUser, { id }, { enabled: id !== '' })
}

export function useListRoles() {
  return useQuery(AdminService.method.listRoles, {})
}

export function useListServiceAccounts() {
  return useQuery(AdminService.method.listServiceAccounts, {})
}

export function useListServiceAccountTokens(id: string) {
  return useQuery(AdminService.method.listServiceAccountTokens, { id }, { enabled: id !== '' })
}

export function useAddUser() {
  const invalidate = useInvalidateUsers()

  return useMutation(AdminService.method.addUser, { onSuccess: invalidate })
}

export function useUpdateUser() {
  const invalidate = useInvalidateUsers()

  return useMutation(AdminService.method.updateUser, { onSuccess: invalidate })
}

export function useDeleteUser() {
  const invalidate = useInvalidateUsers()

  return useMutation(AdminService.method.deleteUser, { onSuccess: invalidate })
}

export function useBecomeMaintainer() {
  const invalidate = useInvalidateUsers()

  return useMutation(AdminService.method.becomeMaintainer, { onSuccess: invalidate })
}

export function useToggleAdmin() {
  const invalidate = useInvalidateUsers()

  return useMutation(AdminService.method.toggleAdmin, { onSuccess: invalidate })
}

export function useCreateServiceAccount() {
  const invalidate = useInvalidateUsers()

  return useMutation(AdminService.method.createServiceAccount, { onSuccess: invalidate })
}

export function useCreateServiceAccountToken() {
  const queryClient = useQueryClient()

  return useMutation(AdminService.method.createServiceAccountToken, {
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: createConnectQueryKey({
          schema: AdminService.method.listServiceAccountTokens,
          cardinality: 'finite',
        }),
      })
    },
  })
}

// A user appears in every listing, so a change to one of them invalidates all of them.
function useInvalidateUsers() {
  const queryClient = useQueryClient()

  return () => {
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({
        schema: AdminService.method.listUsers,
        cardinality: 'finite',
      }),
    })
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({
        schema: AdminService.method.listRoles,
        cardinality: 'finite',
      }),
    })
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({
        schema: AdminService.method.listServiceAccounts,
        cardinality: 'finite',
      }),
    })
    void queryClient.invalidateQueries({
      queryKey: createConnectQueryKey({
        schema: AdminService.method.getUser,
        cardinality: 'finite',
      }),
    })
  }
}
