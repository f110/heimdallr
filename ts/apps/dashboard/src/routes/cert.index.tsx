import { createFileRoute } from '@tanstack/react-router'

import { CertIndexPage } from '../pages/cert'

export const Route = createFileRoute('/cert/')({ component: CertIndexPage })
