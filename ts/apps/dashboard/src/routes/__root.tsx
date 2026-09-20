import { AppShell, Burger, Container, Group, Text } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import {
  IconCertificate,
  IconCopy,
  IconDeviceDesktop,
  IconFileText,
  IconHome,
  IconUser,
} from '@tabler/icons-react'
import { Outlet, createRootRoute, useRouterState } from '@tanstack/react-router'

import { NavLinkLink } from '../components/Link'
import classes from '../components/Navbar.module.css'
import { semantic } from '../theme'

// The same items and icons as the left menu of the server side rendered dashboard.
const menu = [
  { to: '/me', label: 'Me', icon: IconHome },
  { to: '/user', label: 'User', icon: IconUser },
  { to: '/role', label: 'Role', icon: IconFileText },
  { to: '/sa', label: 'Service Account', icon: IconDeviceDesktop },
  { to: '/cert', label: 'Client Certificate', icon: IconCertificate },
  { to: '/agent', label: 'Agent', icon: IconCopy },
]

export const Route = createRootRoute({ component: RootLayout })

function RootLayout() {
  const [opened, { toggle, close }] = useDisclosure()
  const pathname = useRouterState({ select: (s) => s.location.pathname })

  return (
    <AppShell
      header={{ height: 48, collapsed: true }}
      navbar={{
        width: semantic.sidebarWidth,
        breakpoint: 'sm',
        collapsed: { mobile: !opened, desktop: false },
      }}
      padding={0}
    >
      <AppShell.Header withBorder={false} hiddenFrom="sm">
        <Group h="100%" px="md">
          <Burger opened={opened} onClick={toggle} size="sm" />
          <Text fw={700}>Heimdallr</Text>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar className={classes.navbar} py={0}>
        {menu.map((v) => (
          <NavLinkLink
            key={v.to}
            to={v.to}
            label={v.label}
            className={classes.link}
            leftSection={<v.icon size={16} stroke={1.8} />}
            onClick={close}
            active={pathname === v.to || pathname.startsWith(`${v.to}/`)}
          />
        ))}
      </AppShell.Navbar>

      <AppShell.Main>
        <Container size={semantic.containerWidth} pt="2rem" pb="4rem" px="md">
          <Outlet />
        </Container>
      </AppShell.Main>
    </AppShell>
  )
}
