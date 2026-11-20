import { saveBlobWithFallback } from '../../utils/desktop'

export function download(text: string, name: string, type: string) {
  void saveBlobWithFallback(new Blob([text], { type }), name)
}
