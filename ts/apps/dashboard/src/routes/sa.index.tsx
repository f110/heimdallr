import { createFileRoute } from '@tanstack/react-router'

import { ServiceAccountIndexPage } from '../pages/serviceAccount'

export const Route = createFileRoute('/sa/')({ component: ServiceAccountIndexPage })
