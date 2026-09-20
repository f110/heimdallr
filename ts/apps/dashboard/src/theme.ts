import { createTheme } from '@mantine/core'

// The values come from Semantic UI 2.4.2, which the server side rendered dashboard used.
export const semantic = {
  sidebarBackground: '#1b1c1d',
  sidebarColor: 'rgba(255, 255, 255, 0.9)',
  sidebarHoverBackground: 'rgba(255, 255, 255, 0.08)',
  sidebarActiveBackground: 'rgba(255, 255, 255, 0.15)',
  sidebarWidth: 210,
  containerWidth: 1127,
  text: 'rgba(0, 0, 0, 0.87)',
}

export const theme = createTheme({
  fontFamily: "Lato, 'Helvetica Neue', Arial, Helvetica, sans-serif",
  headings: { fontFamily: "Lato, 'Helvetica Neue', Arial, Helvetica, sans-serif" },
  fontSizes: { sm: '14px' },
  primaryColor: 'blue',
  // blue[7] is the closest to the #2185d0 of Semantic UI.
  primaryShade: 7,
  black: semantic.text,
  defaultRadius: 'sm',
})
