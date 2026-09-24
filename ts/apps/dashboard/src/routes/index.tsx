import { SimpleGrid, Text } from '@mantine/core'
import { createFileRoute } from '@tanstack/react-router'

import { ButtonLink } from '../components/Link'
import { Page, Section } from '../components/Page'

export const Route = createFileRoute('/')({ component: Index })

const shortcuts = [
  { to: '/me', title: 'Me', description: 'Your devices and the services you can reach' },
  { to: '/user', title: 'User', description: 'Users and their privileges' },
  { to: '/role', title: 'Role', description: 'Members of each role' },
  { to: '/sa', title: 'Service Account', description: 'Accounts for machines' },
  { to: '/cert', title: 'Client Certificate', description: 'Issued and revoked certificates' },
  { to: '/agent', title: 'Agent', description: 'Connected agents and their certificates' },
]

function Index() {
  return (
    <Page title="Heimdallr Dashboard">
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} spacing="md">
        {shortcuts.map((v) => (
          <Section
            key={v.to}
            title={v.title}
            actions={
              <ButtonLink to={v.to} variant="light" size="compact-sm">
                Open
              </ButtonLink>
            }
          >
            <Text size="sm" c="dimmed">
              {v.description}
            </Text>
          </Section>
        ))}
      </SimpleGrid>
    </Page>
  )
}
