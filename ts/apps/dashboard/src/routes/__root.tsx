import { AppShell, Burger, Group, NavLink, Title } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { Link, Outlet, createRootRoute, useRouterState } from '@tanstack/react-router'

const menu = [
  { to: '/me', label: 'Me' },
  { to: '/user', label: 'User' },
  { to: '/role', label: 'Role' },
  { to: '/sa', label: 'Service Account' },
  { to: '/cert', label: 'Client Certificate' },
  { to: '/agent', label: 'Agent' },
]

export const Route = createRootRoute({ component: RootLayout })

function RootLayout() {
  const [opened, { toggle }] = useDisclosure()
  const pathname = useRouterState({ select: (s) => s.location.pathname })

  return (
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 220, breakpoint: 'sm', collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md">
          <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
          <Title order={4}>Heimdallr</Title>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar>
        {menu.map((v) => (
          <NavLink
            key={v.to}
            component={Link}
            to={v.to}
            label={v.label}
            active={pathname === v.to || pathname.startsWith(`${v.to}/`)}
          />
        ))}
      </AppShell.Navbar>

      <AppShell.Main>
        <Outlet />
      </AppShell.Main>
    </AppShell>
  )
}
