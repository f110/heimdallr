import { createFileRoute } from '@tanstack/react-router'

import { UserIndexPage } from '../pages/user'

export const Route = createFileRoute('/user/')({ component: UserIndexPage })
