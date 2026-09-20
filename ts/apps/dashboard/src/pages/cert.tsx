import {
  Alert,
  Button,
  Group,
  NumberInput,
  Select,
  Stack,
  Textarea,
  TextInput,
} from '@mantine/core'
import { useForm } from '@mantine/form'
import { useNavigate } from '@tanstack/react-router'

import { RevokedCertificateTable, SignedCertificateTable } from '../components/CertificateTable'
import { ButtonLink } from '../components/Link'
import { Page, QueryResult, Section } from '../components/Page'
import { KeyType } from '../connect/dashboard_pb'
import {
  useListCertificates,
  useNewClientCertificate,
  useRevokeCertificate,
} from '../hooks/certificate'

export function CertIndexPage() {
  const query = useListCertificates()
  const revoke = useRevokeCertificate()

  return (
    <Page
      title="Manage Certificate"
      actions={
        <ButtonLink to="/cert/new" variant="light">
          Issue
        </ButtonLink>
      }
    >
      <QueryResult query={query}>
        {(data) => (
          <Stack gap="md">
            <Section title="Signed">
              <SignedCertificateTable
                certificates={data.signed}
                revoking={revoke.isPending}
                onRevoke={(serialNumber) => revoke.mutate({ serialNumber })}
              />
            </Section>
            <Section title="Revoked">
              <RevokedCertificateTable certificates={data.revoked} />
            </Section>
          </Stack>
        )}
      </QueryResult>
    </Page>
  )
}

export function CertNewPage() {
  const navigate = useNavigate()
  const newCert = useNewClientCertificate()
  const form = useForm({
    initialValues: {
      id: '',
      csr: '',
      keyType: String(KeyType.ECDSA),
      keyBits: 256,
      password: '',
      comment: '',
    },
    validate: { id: (v) => (v.trim() === '' ? 'Id is required' : null) },
  })
  const withCSR = form.values.csr.trim() !== ''

  return (
    <Page title="Issue new client certificate">
      <form
        onSubmit={form.onSubmit((values) => {
          newCert.mutate(
            {
              id: values.id,
              csr: values.csr,
              keyType: Number(values.keyType),
              keyBits: values.keyBits,
              password: values.password,
              comment: values.comment,
            },
            { onSuccess: () => void navigate({ to: '/cert' }) },
          )
        })}
      >
        <Stack gap="md">
          {newCert.error ? (
            <Alert color="red" title="Failed to issue the certificate">
              {newCert.error.message}
            </Alert>
          ) : null}

          <Section title="Subject">
            <Stack gap="md" maw={640}>
              <TextInput label="Id" placeholder="Email" {...form.getInputProps('id')} />
              <Textarea
                label="CSR"
                description="Optional. The key and the password below are ignored when it is given."
                placeholder="-----BEGIN CERTIFICATE REQUEST-----"
                autosize
                minRows={6}
                {...form.getInputProps('csr')}
              />
              <Textarea label="Comment" autosize minRows={2} {...form.getInputProps('comment')} />
            </Stack>
          </Section>

          <Section title="Key">
            <Group gap="md" align="flex-end" maw={640} wrap="nowrap">
              <Select
                label="Type"
                w={160}
                disabled={withCSR}
                allowDeselect={false}
                data={[
                  { value: String(KeyType.ECDSA), label: 'ECDSA' },
                  { value: String(KeyType.RSA), label: 'RSA' },
                ]}
                {...form.getInputProps('keyType')}
              />
              <NumberInput
                label="Bits"
                w={120}
                disabled={withCSR}
                {...form.getInputProps('keyBits')}
              />
              <TextInput
                label="Password"
                placeholder="Used for the p12 file"
                disabled={withCSR}
                flex={1}
                {...form.getInputProps('password')}
              />
            </Group>
          </Section>

          <Group gap="xs">
            <Button type="submit" loading={newCert.isPending}>
              Issue
            </Button>
            <ButtonLink to="/cert" variant="default">
              Cancel
            </ButtonLink>
          </Group>
        </Stack>
      </form>
    </Page>
  )
}
