import {
  Alert,
  Button,
  Code,
  CopyButton,
  Group,
  Modal,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
} from '@mantine/core'
import { useForm } from '@mantine/form'
import { useDisclosure } from '@mantine/hooks'
import { useNavigate } from '@tanstack/react-router'

import { AnchorLink, ButtonLink } from '../components/Link'
import { DataTable, Empty, Page, QueryResult, Section } from '../components/Page'
import { formatTimestamp } from '../format'
import {
  useCreateServiceAccount,
  useCreateServiceAccountToken,
  useDeleteUser,
  useListServiceAccounts,
  useListServiceAccountTokens,
} from '../hooks/admin'

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
                          <ButtonLink
                            to="/service_account/$id/token"
                            params={{ id: v.id }}
                            variant="subtle"
                            size="compact-sm"
                          >
                            Token
                          </ButtonLink>
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

export function ServiceAccountTokenPage({ id }: { id: string }) {
  const query = useListServiceAccountTokens(id)
  const [opened, { open, close }] = useDisclosure(false)
  const createToken = useCreateServiceAccountToken()

  return (
    <Page
      title={id}
      actions={
        <>
          <ButtonLink to="/sa" variant="default">
            Back
          </ButtonLink>
          <Button variant="light" onClick={open}>
            New token
          </Button>
        </>
      }
    >
      <NewTokenModal id={id} opened={opened} onClose={close} createToken={createToken} />

      <Stack gap="md">
        {createToken.data ? (
          <Alert color="green" title={`Created ${createToken.data.name}`}>
            <Stack gap="xs" align="flex-start">
              <Text size="sm">The value is shown only once. Copy it now.</Text>
              <Group gap="xs">
                <Code>{createToken.data.value}</Code>
                <CopyButton value={createToken.data.value}>
                  {({ copied, copy }) => (
                    <Button size="compact-sm" variant="light" onClick={copy}>
                      {copied ? 'Copied' : 'Copy'}
                    </Button>
                  )}
                </CopyButton>
              </Group>
            </Stack>
          </Alert>
        ) : null}

        <Section title="Tokens">
          <QueryResult query={query}>
            {(data) =>
              data.tokens.length === 0 ? (
                <Empty>No token has been issued</Empty>
              ) : (
                <DataTable>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Name</Table.Th>
                      <Table.Th>Issuer</Table.Th>
                      <Table.Th>Issued at</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {data.tokens.map((v) => (
                      <Table.Tr key={`${v.name}-${v.issuedAt?.seconds}`}>
                        <Table.Td>{v.name}</Table.Td>
                        <Table.Td>{v.issuer}</Table.Td>
                        <Table.Td>
                          <Text size="sm" c="dimmed">
                            {formatTimestamp(v.issuedAt)}
                          </Text>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </DataTable>
              )
            }
          </QueryResult>
        </Section>
      </Stack>
    </Page>
  )
}

function NewTokenModal({
  id,
  opened,
  onClose,
  createToken,
}: {
  id: string
  opened: boolean
  onClose: () => void
  createToken: ReturnType<typeof useCreateServiceAccountToken>
}) {
  const form = useForm({
    initialValues: { name: '' },
    validate: { name: (v) => (v.trim() === '' ? 'Name is required' : null) },
  })

  return (
    <Modal opened={opened} onClose={onClose} title="New token">
      <form
        onSubmit={form.onSubmit((values) => {
          createToken.mutate(
            { id, name: values.name },
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
          {createToken.error ? (
            <Alert color="red" title="Failed to create the token">
              {createToken.error.message}
            </Alert>
          ) : null}
          <TextInput
            label="Name"
            placeholder="What's use for?"
            data-autofocus
            {...form.getInputProps('name')}
          />
          <Group justify="flex-end" gap="xs">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={createToken.isPending}>
              Create
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
