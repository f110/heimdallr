import {
  Alert,
  Anchor,
  Button,
  Group,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
} from '@mantine/core'
import { useForm } from '@mantine/form'
import { useNavigate } from '@tanstack/react-router'

import { ButtonLink } from '../components/Link'
import { DataTable, Empty, Page, QueryResult, Section } from '../components/Page'
import { certificateDownloadUrl, formatTimestamp } from '../format'
import { useAddDevice, useGetMe } from '../hooks/me'

export function MeIndexPage() {
  const query = useGetMe()

  return (
    <Page title="Me">
      <QueryResult query={query}>
        {(data) => (
          <Stack gap="md">
            <Section
              title="Devices"
              actions={
                <ButtonLink to="/me/device/new" variant="light" size="compact-sm">
                  Add device
                </ButtonLink>
              }
            >
              {data.devices.length === 0 ? (
                <Empty>No device has been registered</Empty>
              ) : (
                <DataTable>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Name</Table.Th>
                      <Table.Th>Registered at</Table.Th>
                      <Table.Th w={120}>Download</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {data.devices.map((v) => (
                      <Table.Tr key={v.serialNumber}>
                        <Table.Td>
                          {v.comment || (
                            <Text size="sm" c="dimmed">
                              (no name)
                            </Text>
                          )}
                        </Table.Td>
                        <Table.Td>
                          <Text size="sm" c="dimmed">
                            {formatTimestamp(v.issuedAt)}
                          </Text>
                        </Table.Td>
                        <Table.Td>
                          <Anchor href={certificateDownloadUrl(v.serialNumber, 'cert')}>
                            cert
                          </Anchor>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </DataTable>
              )}
            </Section>

            <Section title="Services">
              {data.backends.length === 0 ? (
                <Empty>No backend is reachable</Empty>
              ) : (
                <DataTable>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Name</Table.Th>
                      <Table.Th>Description</Table.Th>
                      <Table.Th>URL</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {data.backends.map((v) => (
                      <Table.Tr key={v.name}>
                        <Table.Td>{v.name}</Table.Td>
                        <Table.Td>
                          <Text size="sm" c="dimmed">
                            {v.description}
                          </Text>
                        </Table.Td>
                        <Table.Td>
                          <Anchor href={`https://${v.host}`}>https://{v.host}</Anchor>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </DataTable>
              )}
            </Section>
          </Stack>
        )}
      </QueryResult>
    </Page>
  )
}

export function MeDeviceNewPage() {
  const navigate = useNavigate()
  const addDevice = useAddDevice()
  const form = useForm({
    initialValues: { name: '', csr: '' },
    validate: { csr: (v) => (v.trim() === '' ? 'CSR is required' : null) },
  })

  return (
    <Page title="Add device">
      <Section title="Certificate signing request">
        <form
          onSubmit={form.onSubmit((values) => {
            addDevice.mutate(values, { onSuccess: () => void navigate({ to: '/me' }) })
          })}
        >
          <Stack gap="md" maw={640}>
            {addDevice.error ? (
              <Alert color="red" title="Failed to add the device">
                {addDevice.error.message}
              </Alert>
            ) : null}
            <TextInput label="Name" placeholder="My laptop" {...form.getInputProps('name')} />
            <Textarea
              label="CSR"
              placeholder="-----BEGIN CERTIFICATE REQUEST-----"
              autosize
              minRows={8}
              {...form.getInputProps('csr')}
            />
            <Group gap="xs">
              <Button type="submit" loading={addDevice.isPending}>
                Add
              </Button>
              <ButtonLink to="/me" variant="default">
                Cancel
              </ButtonLink>
            </Group>
          </Stack>
        </form>
      </Section>
    </Page>
  )
}
