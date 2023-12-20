import {Component, Input} from "@angular/core";
import {UtilsService} from "@app/shared/services/utils.service";
import {WbtipService} from "@app/services/wbtip.service";
import {HttpService} from "@app/shared/services/http.service";
import {AppDataService} from "@app/app-data.service";
import {CryptoService} from "@app/crypto.service";
import {AuthenticationService} from "@app/services/authentication.service";
import { WbFile } from "@app/models/app/shared-public-model";

@Component({
  selector: "src-tip-files-whistleblower",
  templateUrl: "./tip-files-whistleblower.component.html"
})
export class TipFilesWhistleblowerComponent {
  @Input() fileUploadUrl: string;
  collapsed = false;

  constructor(private appDataService: AppDataService, private cryptoService: CryptoService, private httpService: HttpService, protected authenticationService: AuthenticationService, protected utilsService: UtilsService, protected wbTipService: WbtipService) {
  }

  downloadWBFile(wbFile: WbFile) {

    const param = JSON.stringify({});
    this.httpService.requestToken(param).subscribe
    (
        {
          next: async token => {
            const ans = await this.cryptoService.proofOfWork(token.id);
            window.open("api/whistleblower/wbtip/wbfiles/" + wbFile.id + "?token=" + token.id + ":" + ans);
            this.appDataService.updateShowLoadingPanel(false);
          }
        }
    );
  }

  public toggleColLapse() {
    this.collapsed = !this.collapsed;
  }
}
