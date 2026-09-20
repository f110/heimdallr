import { Alert, Center, Divider, Group, Loader, Stack, Table, Text, Title } from '@mantine/core'
import type { ReactNode } from 'react'

export function Page({
  title,
  actions,
  children,
}: {
  title: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <Stack gap="md">
      <Group justify="space-between" align="center" wrap="nowrap">
        <Title order={2}>{title}</Title>
        {actions ? (
          <Group gap="xs" wrap="nowrap">
            {actions}
          </Group>
        ) : null}
      </Group>
      <Divider />
      {children}
    </Stack>
  )
}

export function Section({
  title,
  actions,
  children,
}: {
  title?: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <Stack gap="xs">
      {title || actions ? (
        <Group justify="space-between" align="center" wrap="nowrap">
          {title ? <Title order={3}>{title}</Title> : <span />}
          {actions ? (
            <Group gap="xs" wrap="nowrap">
              {actions}
            </Group>
          ) : null}
        </Group>
      ) : null}
      {children}
    </Stack>
  )
}

export function DataTable({ celled, children }: { celled?: boolean; children: ReactNode }) {
  return (
    <Table striped highlightOnHover withTableBorder withColumnBorders={celled} verticalSpacing="sm">
      {children}
    </Table>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <Center py="xl">
      <Text size="sm" c="dimmed">
        {children}
      </Text>
    </Center>
  )
}

export function QueryResult<T>({
  query,
  children,
}: {
  query: { data?: T; isPending: boolean; error: Error | null }
  children: (data: T) => ReactNode
}) {
  if (query.error) {
    return (
      <Alert color="red" title="Failed to load">
        {query.error.message}
      </Alert>
    )
  }
  if (query.isPending || query.data === undefined) {
    return (
      <Center py="xl">
        <Loader />
      </Center>
    )
  }

  return <>{children(query.data)}</>
}
