import { Anchor, Button, NavLink } from '@mantine/core'
import type { AnchorProps, ButtonProps, NavLinkProps } from '@mantine/core'
import { createLink } from '@tanstack/react-router'
import { forwardRef } from 'react'
import type { AnchorHTMLAttributes } from 'react'

type AnchorAttributes = AnchorHTMLAttributes<HTMLAnchorElement>

const MantineAnchor = forwardRef<HTMLAnchorElement, AnchorProps & AnchorAttributes>(
  (props, ref) => <Anchor ref={ref} {...props} />,
)
MantineAnchor.displayName = 'MantineAnchor'

const MantineButton = forwardRef<HTMLAnchorElement, ButtonProps & AnchorAttributes>(
  (props, ref) => <Button component="a" ref={ref} {...props} />,
)
MantineButton.displayName = 'MantineButton'

const MantineNavLink = forwardRef<HTMLAnchorElement, NavLinkProps & AnchorAttributes>(
  (props, ref) => <NavLink component="a" ref={ref} {...props} />,
)
MantineNavLink.displayName = 'MantineNavLink'

export const AnchorLink = createLink(MantineAnchor)
export const ButtonLink = createLink(MantineButton)
export const NavLinkLink = createLink(MantineNavLink)
