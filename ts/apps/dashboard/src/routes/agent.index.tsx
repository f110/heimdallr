import { createFileRoute } from '@tanstack/react-router'

import { AgentIndexPage } from '../pages/agent'

export const Route = createFileRoute('/agent/')({ component: AgentIndexPage })
