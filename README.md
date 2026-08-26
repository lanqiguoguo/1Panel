<p align="center"><b>1Panel</b></p>
<p align="center"><b>Simplify Linux Server Management</b></p>

------------------------------

Internal fork of [1Panel-dev/1Panel](https://github.com/1Panel-dev/1Panel) (v1 line).

Differences from upstream:

- **Self-hosted release channel**: panel online upgrades are served from this repository — version manifests and release notes via raw (`stable/`、`dev/`, mirrored), packages attached to the rolling GitHub Release tag `packages`. No dependency on `resource.1panel.pro`.
- **Self-hosted app store**: app store source lives at [lanqiguoguo/appstore](https://github.com/lanqiguoguo/appstore).
- **Pro/xpack features removed**: WAF-related professional add-ons are stripped; packaging pulls nothing from official repos or fit2cloud.
- Versioning: `v1.10.{x}-lts`, monotonically increasing, independent from upstream tags.

## Quick Start

Install the latest stable version:

```bash
curl -sSL https://raw.githubusercontent.com/lanqiguoguo/1Panel/main/install.sh -o install.sh && sudo bash install.sh
```

Or install a specific version:

```bash
sudo bash install.sh v1.10.35-lts
```

If GitHub is slow or unreachable from your network, pass an explicit proxy
(this survives `sudo`, unlike exported environment variables):

```bash
sudo bash install.sh --proxy http://127.0.0.1:7890
```

Fully offline install from a manually downloaded package:

```bash
sudo bash install.sh --pkg ./1panel-v1.10.35-lts-linux-amd64.tar.gz
```

Non-interactive install (all prompts can be pre-set via environment):

```bash
sudo PANEL_BASE_DIR=/opt PANEL_PORT=9999 PANEL_USERNAME=admin PANEL_PASSWORD='Admin@2026' \
    PANEL_ENTRANCE=entrance bash install.sh
```

Uninstall:

```bash
sudo bash install.sh -u
```

### Online Upgrade

Once installed, check and apply upgrades inside the panel (footer or `Settings -> About`).
Upgrades download the new build from this repository's release channel and keep your local
settings (port, credentials, entrance) intact.

## Development

- Local development runs with embedded `mode: dev`; released builds switch to `stable` during CI.
- Publishing a release = pushing a tag matching `v1.10.*-lts`; GitHub Actions builds, assembles
  the package and refreshes both channel trees automatically.
- Packaging assets (1pctl template, init scripts, lang files, GeoIP database) live under `ci/resources/`.

## Security Information

If you discover any security issues, please refer to [SECURITY.md](/SECURITY.md).

## License

Licensed under The GNU General Public License version 3 (GPLv3)  (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

<https://www.gnu.org/licenses/gpl-3.0.html>

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
