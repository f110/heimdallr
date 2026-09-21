import { Alert, Button, Group, Stack, Table, Text, Textarea, Select } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useNavigate } from '@tanstack/react-router'

import { RevokedCertificateTable, SignedCertificateTable } from '../components/CertificateTable'
import { ButtonLink } from '../components/Link'
import { DataTable, Empty, Page, QueryResult, Section } from '../components/Page'
import { formatTimestamp } from '../format'
import {
  useListAgentBackends,
  useListAgents,
  useRegisterAgent,
  useRevokeCertificate,
} from '../hooks/certificate'

export function AgentIndexPage() {
  const query = useListAgents()
  const revoke = useRevokeCertificate()

  return (
    <Page
      title="Manage Agent"
      actions={
        <>
          <Button component="a" href="/cert/ca" variant="default">
            CA certificate
          </Button>
          <ButtonLink to="/agent/new" variant="light">
            Register
          </ButtonLink>
        </>
      }
    >
      <QueryResult query={query}>
        {(data) => (
          <Stack gap="md">
            <Section title="Connected">
              {data.connected.length === 0 ? (
                <Empty>No agent is connected</Empty>
              ) : (
                <DataTable>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Name</Table.Th>
                      <Table.Th>Remote IP</Table.Th>
                      <Table.Th>Connected at</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {data.connected.map((v) => (
                      <Table.Tr key={`${v.name}-${v.fromAddr}`}>
                        <Table.Td>{v.name}</Table.Td>
                        <Table.Td>
                          <Text ff="monospace" size="sm">
                            {v.fromAddr}
                          </Text>
                        </Table.Td>
                        <Table.Td>
                          <Text size="sm" c="dimmed">
                            {formatTimestamp(v.connectedAt)}
                          </Text>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </DataTable>
              )}
            </Section>

            <Section title="Signed">
              <SignedCertificateTable
                certificates={data.signed}
                revoking={revoke.isPending}
                onRevoke={(serialNumber) => revoke.mutate({ serialNumber })}
              />
            </Section>

            <Section title="Revoked">
              <RevokedCertificateTable certificates={data.revoked} />
            </Section>
          </Stack>
        )}
      </QueryResult>
    </Page>
  )
}

export function AgentNewPage() {
  const navigate = useNavigate()
  const backends = useListAgentBackends()
  const register = useRegisterAgent()
  const form = useForm({
    initialValues: { id: '', csr: '', comment: '' },
    validate: { id: (v) => (v.trim() === '' ? 'Agent is required' : null) },
  })

  return (
    <Page title="Register agent">
      <Section title="Agent">
        <form
          onSubmit={form.onSubmit((values) => {
            register.mutate(values, { onSuccess: () => void navigate({ to: '/agent' }) })
          })}
        >
          <Stack gap="md" maw={640}>
            {register.error ? (
              <Alert color="red" title="Failed to register the agent">
                {register.error.message}
              </Alert>
            ) : null}
            <Select
              label="Backend"
              placeholder="Pick one"
              data={backends.data?.names ?? []}
              searchable
              {...form.getInputProps('id')}
            />
            <Textarea
              label="CSR"
              description="Optional"
              placeholder="-----BEGIN CERTIFICATE REQUEST-----"
              autosize
              minRows={6}
              {...form.getInputProps('csr')}
            />
            <Textarea label="Comment" autosize minRows={2} {...form.getInputProps('comment')} />
            <Group gap="xs">
              <Button type="submit" loading={register.isPending}>
                Register
              </Button>
              <ButtonLink to="/agent" variant="default">
                Cancel
              </ButtonLink>
            </Group>
          </Stack>
        </form>
      </Section>
    </Page>
  )
}
