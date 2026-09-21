import { createFileRoute } from '@tanstack/react-router'

import { UserShowPage } from '../pages/user'

export const Route = createFileRoute('/user/$id/')({ component: Show })

function Show() {
  const { id } = Route.useParams()
  return <UserShowPage id={id} />
}
