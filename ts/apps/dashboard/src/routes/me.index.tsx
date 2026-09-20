import { createFileRoute } from '@tanstack/react-router'

import { MeIndexPage } from '../pages/me'

export const Route = createFileRoute('/me/')({ component: MeIndexPage })
