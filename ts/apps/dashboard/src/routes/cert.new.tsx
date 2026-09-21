import { createFileRoute } from '@tanstack/react-router'

import { CertNewPage } from '../pages/cert'

export const Route = createFileRoute('/cert/new')({ component: CertNewPage })
