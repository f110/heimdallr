import { createFileRoute } from '@tanstack/react-router'

import { AgentNewPage } from '../pages/agent'

export const Route = createFileRoute('/agent/new')({ component: AgentNewPage })
