import { createFileRoute } from '@tanstack/react-router'

import { ServiceAccountTokenPage } from '../pages/serviceAccount'

export const Route = createFileRoute('/service_account/$id/token')({ component: Token })

function Token() {
  const { id } = Route.useParams()
  return <ServiceAccountTokenPage id={id} />
}
