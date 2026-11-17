import './style.css'
import QRCode from 'qrcode'
import { squareThumb } from './src/image.js'

// Scala.js の画面から使う補助（QR コード・画像の縮小）
window.sruruQr = { toDataURL: (text, opts) => QRCode.toDataURL(text, opts ?? { margin: 1, width: 200 }) }
window.sruruImage = { squareThumb }

import 'scalajs:main.js'
