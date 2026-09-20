import { Alert, Badge, Button, Group, Modal, Select, Stack, Table, TextInput } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useDisclosure } from '@mantine/hooks'
import { useState } from 'react'

import { AnchorLink } from '../components/Link'
import { DataTable, Empty, Page, QueryResult, Section } from '../components/Page'
import type { RoleMembers } from '../connect/dashboard_pb'
import { UserType } from '../connect/dashboard_pb'
import { useAddUser, useBecomeMaintainer, useDeleteUser, useListRoles } from '../hooks/admin'

const allRoles = '_all'

export function RolePage() {
  const query = useListRoles()
  const [filter, setFilter] = useState(allRoles)

  return (
    <Page
      title="Manage Role"
      actions={
        <Select
          w={220}
          aria-label="Filter by role"
          allowDeselect={false}
          value={filter}
          onChange={(v) => setFilter(v ?? allRoles)}
          data={[
            { value: allRoles, label: 'All roles' },
            ...(query.data?.roles ?? []).map((v) => ({
              value: v.role?.name ?? '',
              label: v.role?.title || (v.role?.name ?? ''),
            })),
          ]}
        />
      }
    >
      <QueryResult query={query}>
        {(data) => (
          <Stack gap="md">
            {data.roles
              .filter((v) => filter === allRoles || v.role?.name === filter)
              .map((v) => (
                <RoleSection key={v.role?.name} role={v} />
              ))}
          </Stack>
        )}
      </QueryResult>
    </Page>
  )
}

function RoleSection({ role }: { role: RoleMembers }) {
  const name = role.role?.name ?? ''
  const [opened, { open, close }] = useDisclosure(false)
  const becomeMaintainer = useBecomeMaintainer()
  const deleteUser = useDeleteUser()

  return (
    <Section
      title={role.role?.title || name}
      actions={
        <Button size="compact-sm" variant="light" onClick={open}>
          Add User
        </Button>
      }
    >
      <AddUserModal role={name} opened={opened} onClose={close} />

      {role.members.length === 0 ? (
        <Empty>No user belongs to this role</Empty>
      ) : (
        <DataTable>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Id</Table.Th>
              <Table.Th w={220} />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {role.members.map((v) => (
              <Table.Tr key={v.id}>
                <Table.Td>
                  <Group gap="sm">
                    <AnchorLink to="/user/$id" params={{ id: v.id }}>
                      {v.id}
                    </AnchorLink>
                    {v.maintainer ? (
                      <Badge color="green" variant="light">
                        Maintainer
                      </Badge>
                    ) : null}
                    {v.admin ? (
                      <Badge color="blue" variant="light">
                        Admin
                      </Badge>
                    ) : null}
                    {v.type === UserType.SERVICE_ACCOUNT ? (
                      <Badge color="pink" variant="light">
                        ServiceAccount
                      </Badge>
                    ) : null}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Group gap="xs" justify="flex-end" wrap="nowrap">
                    {v.maintainer ? null : (
                      <Button
                        variant="subtle"
                        size="compact-sm"
                        onClick={() => becomeMaintainer.mutate({ id: v.id, role: name })}
                      >
                        Maintainer
                      </Button>
                    )}
                    <Button
                      color="red"
                      variant="subtle"
                      size="compact-sm"
                      onClick={() => deleteUser.mutate({ id: v.id, role: name })}
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
  )
}

function AddUserModal({
  role,
  opened,
  onClose,
}: {
  role: string
  opened: boolean
  onClose: () => void
}) {
  const addUser = useAddUser()
  const form = useForm({
    initialValues: { id: '' },
    validate: { id: (v) => (v.trim() === '' ? 'Id is required' : null) },
  })

  return (
    <Modal opened={opened} onClose={onClose} title={`Add a user to ${role}`}>
      <form
        onSubmit={form.onSubmit((values) => {
          addUser.mutate(
            { id: values.id, role },
            {
              onSuccess: () => {
                form.reset()
                onClose()
              },
            },
          )
        })}
      >
        <Stack gap="md">
          {addUser.error ? (
            <Alert color="red" title="Failed to add the user">
              {addUser.error.message}
            </Alert>
          ) : null}
          <TextInput label="Id" placeholder="Email" data-autofocus {...form.getInputProps('id')} />
          <Group justify="flex-end" gap="xs">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={addUser.isPending}>
              Add
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
