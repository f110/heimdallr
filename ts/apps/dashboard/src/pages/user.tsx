import { Alert, Anchor, Badge, Button, Group, Stack, Table, Text, TextInput } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useNavigate } from '@tanstack/react-router'

import { AnchorLink, ButtonLink } from '../components/Link'
import { DataTable, Empty, Page, QueryResult, Section } from '../components/Page'
import type { User } from '../connect/dashboard_pb'
import { UserType } from '../connect/dashboard_pb'
import { formatTimestamp } from '../format'
import {
  useDeleteUser,
  useGetUser,
  useListUsers,
  useToggleAdmin,
  useUpdateUser,
} from '../hooks/admin'

export function UserBadges({ user }: { user: User }) {
  return (
    <>
      {user.admin ? (
        <Badge color="blue" variant="light">
          Admin
        </Badge>
      ) : null}
      {user.type === UserType.SERVICE_ACCOUNT ? (
        <Badge color="pink" variant="light">
          ServiceAccount
        </Badge>
      ) : null}
    </>
  )
}

export function UserIndexPage() {
  const query = useListUsers()
  const toggleAdmin = useToggleAdmin()
  const deleteUser = useDeleteUser()

  return (
    <Page title="Manage User">
      <QueryResult query={query}>
        {(data) => (
          <Section>
            {data.users.length === 0 ? (
              <Empty>No user has been registered</Empty>
            ) : (
              <DataTable>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Id</Table.Th>
                    <Table.Th w={240} />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {data.users.map((v) => (
                    <Table.Tr key={v.id}>
                      <Table.Td>
                        <Group gap="sm">
                          <AnchorLink to="/user/$id" params={{ id: v.id }}>
                            {v.id}
                          </AnchorLink>
                          <UserBadges user={v} />
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Group gap="xs" justify="flex-end" wrap="nowrap">
                          {v.type === UserType.SERVICE_ACCOUNT ? null : (
                            <Button
                              variant="subtle"
                              size="compact-sm"
                              onClick={() => toggleAdmin.mutate({ id: v.id })}
                            >
                              {v.admin ? 'Back to user' : 'Become admin'}
                            </Button>
                          )}
                          <Button
                            color="red"
                            variant="subtle"
                            size="compact-sm"
                            onClick={() => deleteUser.mutate({ id: v.id })}
                          >
                            Delete
                          </Button>
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </DataTable>
            )}
          </Section>
        )}
      </QueryResult>
    </Page>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Table.Tr>
      <Table.Th w={200}>{label}</Table.Th>
      <Table.Td>{children}</Table.Td>
    </Table.Tr>
  )
}

export function UserShowPage({ id }: { id: string }) {
  const query = useGetUser(id)

  return (
    <Page
      title={id}
      actions={
        <ButtonLink to="/user/$id/edit" params={{ id }} variant="light">
          Edit
        </ButtonLink>
      }
    >
      <QueryResult query={query}>
        {(data) => (
          <Stack gap="md">
            <Section title="Profile">
              <Table variant="vertical" withTableBorder verticalSpacing="sm">
                <Table.Tbody>
                  <Field label="Id">{data.user?.id}</Field>
                  <Field label="Type">
                    {data.user ? (
                      <Badge
                        variant="light"
                        color={data.user.type === UserType.SERVICE_ACCOUNT ? 'pink' : 'gray'}
                      >
                        {UserType[data.user.type]}
                      </Badge>
                    ) : null}
                  </Field>
                  <Field label="Role">
                    <Group gap="xs">
                      {data.user?.roles.length === 0 ? (
                        <Text size="sm" c="dimmed">
                          None
                        </Text>
                      ) : null}
                      {data.user?.roles.map((v) => (
                        <Badge
                          key={v}
                          variant="light"
                          color={data.user?.maintainRoles.includes(v) ? 'green' : 'gray'}
                        >
                          {v}
                          {data.user?.maintainRoles.includes(v) ? ' (maintainer)' : ''}
                        </Badge>
                      ))}
                    </Group>
                  </Field>
                  <Field label="Login name">
                    {data.user?.loginName || (
                      <Text size="sm" c="dimmed">
                        Not set
                      </Text>
                    )}
                  </Field>
                  <Field label="Last logged-in">
                    <Text size="sm" c="dimmed">
                      {formatTimestamp(data.user?.lastLogin) || 'Never'}
                    </Text>
                  </Field>
                </Table.Tbody>
              </Table>
            </Section>

            <Section title="Allowed URLs">
              {data.backends.length === 0 ? (
                <Empty>No backend is reachable</Empty>
              ) : (
                <Stack gap="xs">
                  {data.backends.map((v) => (
                    <Anchor key={v.name} href={`https://${v.host}`}>
                      https://{v.host}
                    </Anchor>
                  ))}
                </Stack>
              )}
            </Section>
          </Stack>
        )}
      </QueryResult>
    </Page>
  )
}

export function UserEditPage({ id }: { id: string }) {
  const query = useGetUser(id)

  return (
    <Page title={id}>
      <QueryResult query={query}>
        {(data) => <UserEditForm id={id} loginName={data.user?.loginName ?? ''} />}
      </QueryResult>
    </Page>
  )
}

function UserEditForm({ id, loginName }: { id: string; loginName: string }) {
  const navigate = useNavigate()
  const updateUser = useUpdateUser()
  const form = useForm({ initialValues: { loginName } })

  return (
    <Section title="Edit">
      <form
        onSubmit={form.onSubmit((values) => {
          updateUser.mutate(
            { id, loginName: values.loginName },
            { onSuccess: () => void navigate({ to: '/user/$id', params: { id } }) },
          )
        })}
      >
        <Stack gap="md" maw={480}>
          {updateUser.error ? (
            <Alert color="red" title="Failed to update the user">
              {updateUser.error.message}
            </Alert>
          ) : null}
          <TextInput label="Id" value={id} disabled />
          <TextInput
            label="Login name"
            placeholder="username"
            {...form.getInputProps('loginName')}
          />
          <Group gap="xs">
            <Button type="submit" loading={updateUser.isPending}>
              Save
            </Button>
            <ButtonLink to="/user/$id" params={{ id }} variant="default">
              Cancel
            </ButtonLink>
          </Group>
        </Stack>
      </form>
    </Section>
  )
}
