import { createFileRoute } from '@tanstack/react-router'

import { MeDeviceNewPage } from '../pages/me'

export const Route = createFileRoute('/me/device/new')({ component: MeDeviceNewPage })
