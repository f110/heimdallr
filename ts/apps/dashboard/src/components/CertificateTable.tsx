import { Anchor, Button, Group, Table, Text } from '@mantine/core'

import type { Certificate } from '../connect/dashboard_pb'
import { certificateDownloadUrl, formatTimestamp } from '../format'
import { DataTable, Empty } from './Page'

function SerialNumber({ value }: { value: string }) {
  return (
    <Text ff="monospace" size="sm">
      0x{value}
    </Text>
  )
}

export function SignedCertificateTable({
  certificates,
  onRevoke,
  revoking,
}: {
  certificates: Certificate[]
  onRevoke: (serialNumber: string) => void
  revoking: boolean
}) {
  if (certificates.length === 0) {
    return <Empty>No certificate has been issued</Empty>
  }

  return (
    <DataTable celled>
      <Table.Thead>
        <Table.Tr>
          <Table.Th>Serial Number</Table.Th>
          <Table.Th>Common Name</Table.Th>
          <Table.Th>Issued at</Table.Th>
          <Table.Th>Comment</Table.Th>
          <Table.Th>Download</Table.Th>
          <Table.Th w={100} />
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {certificates.map((v) => (
          <Table.Tr key={v.serialNumber}>
            <Table.Td>
              <SerialNumber value={v.serialNumber} />
            </Table.Td>
            <Table.Td>{v.commonName}</Table.Td>
            <Table.Td>
              <Text size="sm" c="dimmed">
                {formatTimestamp(v.issuedAt)}
              </Text>
            </Table.Td>
            <Table.Td>{v.comment}</Table.Td>
            <Table.Td>
              <Group gap="sm" wrap="nowrap">
                {v.hasP12 ? (
                  <Anchor href={certificateDownloadUrl(v.serialNumber)}>p12</Anchor>
                ) : null}
                <Anchor href={certificateDownloadUrl(v.serialNumber, 'cert')}>cert</Anchor>
              </Group>
            </Table.Td>
            <Table.Td>
              <Group justify="flex-end">
                <Button
                  color="red"
                  variant="subtle"
                  size="compact-sm"
                  disabled={revoking}
                  onClick={() => onRevoke(v.serialNumber)}
                >
                  Revoke
                </Button>
              </Group>
            </Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </DataTable>
  )
}

export function RevokedCertificateTable({ certificates }: { certificates: Certificate[] }) {
  if (certificates.length === 0) {
    return <Empty>No certificate has been revoked</Empty>
  }

  return (
    <DataTable celled>
      <Table.Thead>
        <Table.Tr>
          <Table.Th>Serial Number</Table.Th>
          <Table.Th>Common Name</Table.Th>
          <Table.Th>Issued at</Table.Th>
          <Table.Th>Revoked at</Table.Th>
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {certificates.map((v) => (
          <Table.Tr key={v.serialNumber}>
            <Table.Td>
              <SerialNumber value={v.serialNumber} />
            </Table.Td>
            <Table.Td>{v.commonName}</Table.Td>
            <Table.Td>
              <Text size="sm" c="dimmed">
                {formatTimestamp(v.issuedAt)}
              </Text>
            </Table.Td>
            <Table.Td>
              <Text size="sm" c="dimmed">
                {formatTimestamp(v.revokedAt)}
              </Text>
            </Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </DataTable>
  )
}
