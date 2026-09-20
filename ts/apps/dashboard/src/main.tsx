import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from '@tanstack/react-router'

import { AppProvider } from './providers/AppProvider'
import { router } from './route'

import '@mantine/core/styles.css'

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
