import type { Timestamp } from '@bufbuild/protobuf/wkt'
import { timestampDate } from '@bufbuild/protobuf/wkt'
import dayjs from 'dayjs'

export function formatTimestamp(v?: Timestamp): string {
  if (!v) {
    return ''
  }

  return dayjs(timestampDate(v)).format('YYYY/MM/DD HH:mm:ss Z')
}

export function certificateDownloadUrl(serialNumber: string, format?: 'cert'): string {
  const params = new URLSearchParams({ serial: serialNumber })
  if (format) {
    params.set('format', format)
  }

  return `/cert/download?${params.toString()}`
}
