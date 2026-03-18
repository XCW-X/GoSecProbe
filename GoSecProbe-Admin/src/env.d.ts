declare module '*.vue' {
  import type { DefineComponent } from 'vue'

  const component: DefineComponent<Record<string, unknown>, Record<string, unknown>, any>
  export default component
}

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
  glob: (pattern: string, options?: { eager?: boolean; import?: string }) => Record<string, unknown>
}

declare module '*.png' {
  const src: string
  export default src
}
