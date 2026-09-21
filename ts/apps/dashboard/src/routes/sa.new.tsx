import { createFileRoute } from '@tanstack/react-router'

import { ServiceAccountNewPage } from '../pages/serviceAccount'

export const Route = createFileRoute('/sa/new')({ component: ServiceAccountNewPage })
