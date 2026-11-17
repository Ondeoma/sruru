import { defineConfig } from 'vite'
import scalaJS from './vite-scalajs.js'

const backend = process.env.BACKEND ?? 'http://localhost:9100'

// バックエンドへ転送するパス（API・ログインの途中・各プロトコルのエンドポイント・画像）
const paths = ['/api', '/auth', '/oauth2', '/saml', '/scim', '/mcp', '/.well-known', '/avatars', '/app-icons']

export default defineConfig({
  // 画面(Scalactive)は sbt の web プロジェクトから読み込む
  plugins: [scalaJS({ cwd: '..', projectID: 'web' })],
  server: {
    // IPv4 で待ち受ける（LAN には公開しない）
    host: '127.0.0.1',
    proxy: Object.fromEntries(paths.map((p) => [p, backend])),
  },
  build: { chunkSizeWarningLimit: 2000 },
})
