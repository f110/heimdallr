import { createFileRoute } from '@tanstack/react-router'

import { UserEditPage } from '../pages/user'

export const Route = createFileRoute('/user/$id/edit')({ component: Edit })

function Edit() {
  const { id } = Route.useParams()
  return <UserEditPage id={id} />
}
