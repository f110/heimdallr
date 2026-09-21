// The layered stylesheet puts every rule of Mantine into "@layer mantine", so the CSS modules of
// this app win no matter in which order the bundler emits them.
import '@mantine/core/styles.layer.css'

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from '@tanstack/react-router'

import { AppProvider } from './providers/AppProvider'
import { router } from './route'

const container = document.getElementById('root')
if (!container) {
  throw new Error('dashboard: #root is not found')
}

createRoot(container).render(
  <StrictMode>
    <AppProvider>
      <RouterProvider router={router} />
    </AppProvider>
  </StrictMode>,
)
