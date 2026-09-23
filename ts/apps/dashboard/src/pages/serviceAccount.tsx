import { Alert, Button, Group, Stack, Table, Text, Textarea, TextInput } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useNavigate } from '@tanstack/react-router'

import { AnchorLink, ButtonLink } from '../components/Link'
import { DataTable, Empty, Page, QueryResult, Section } from '../components/Page'
import { useCreateServiceAccount, useDeleteUser, useListServiceAccounts } from '../hooks/admin'

export function ServiceAccountIndexPage() {
  const query = useListServiceAccounts()
  const deleteUser = useDeleteUser()

  return (
    <Page
      title="Manage ServiceAccount"
      actions={
        <ButtonLink to="/sa/new" variant="light">
          New
        </ButtonLink>
      }
    >
      <QueryResult query={query}>
        {(data) => (
          <Section>
            {data.accounts.length === 0 ? (
              <Empty>No service account has been created</Empty>
            ) : (
              <DataTable>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Id</Table.Th>
                    <Table.Th>Comment</Table.Th>
                    <Table.Th w={180} />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {data.accounts.map((v) => (
                    <Table.Tr key={v.id}>
                      <Table.Td>
                        <AnchorLink to="/user/$id" params={{ id: v.id }}>
                          {v.id}
                        </AnchorLink>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" c="dimmed">
                          {v.comment}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Group gap="xs" justify="flex-end" wrap="nowrap">
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

export function ServiceAccountNewPage() {
  const navigate = useNavigate()
  const createServiceAccount = useCreateServiceAccount()
  const form = useForm({
    initialValues: { id: '', comment: '' },
    validate: { id: (v) => (v.trim() === '' ? 'Id is required' : null) },
  })

  return (
    <Page title="Create ServiceAccount">
      <Section title="Account">
        <form
          onSubmit={form.onSubmit((values) => {
            createServiceAccount.mutate(values, { onSuccess: () => void navigate({ to: '/sa' }) })
          })}
        >
          <Stack gap="md" maw={640}>
            {createServiceAccount.error ? (
              <Alert color="red" title="Failed to create the service account">
                {createServiceAccount.error.message}
              </Alert>
            ) : null}
            <TextInput label="Id" placeholder="Email" {...form.getInputProps('id')} />
            <Textarea label="Comment" autosize minRows={2} {...form.getInputProps('comment')} />
            <Group gap="xs">
              <Button type="submit" loading={createServiceAccount.isPending}>
                Create
              </Button>
              <ButtonLink to="/sa" variant="default">
                Cancel
              </ButtonLink>
            </Group>
          </Stack>
        </form>
      </Section>
    </Page>
  )
}
