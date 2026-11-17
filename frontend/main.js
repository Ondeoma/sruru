import './style.css'
import QRCode from 'qrcode'

// Scala.js の画面から使うライブラリ（QR コード）
window.sruruQr = { toDataURL: (text, opts) => QRCode.toDataURL(text, opts ?? { margin: 1, width: 200 }) }

import 'scalajs:main.js'
