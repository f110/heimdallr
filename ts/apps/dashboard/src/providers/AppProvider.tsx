import { MantineProvider } from '@mantine/core'
import { TransportProvider } from '@connectrpc/connect-query'
import { createConnectTransport } from '@connectrpc/connect-web'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'

// The dashboard is served from the same origin as the API, so the browser sends the session
// cookie and authproxy attaches X-Auth-Token on its own.
const transport = createConnectTransport({ baseUrl: '/' })
const queryClient = new QueryClient()

export const AppProvider = ({ children }: { children: ReactNode }) => {
  return (
    <TransportProvider transport={transport}>
      <QueryClientProvider client={queryClient}>
        <MantineProvider>{children}</MantineProvider>
      </QueryClientProvider>
    </TransportProvider>
  )
}
