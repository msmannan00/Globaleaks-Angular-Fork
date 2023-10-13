import {Component, OnInit} from "@angular/core";
import {UtilsService} from "@app/shared/services/utils.service";
import {AuthenticationService} from "@app/services/authentication.service";
import {AppDataService} from "@app/app-data.service";

@Component({
  selector: "src-receipt-whistleblower",
  templateUrl: "./receipt.component.html"
})
export class ReceiptComponent implements OnInit {
  receipt: any;

  constructor(protected utilsService: UtilsService, protected authenticationService: AuthenticationService, protected appDataService: AppDataService) {
  }

  ngOnInit(): void {
    if (this.authenticationService.session.receipt) {
      this.receipt = this.authenticationService.session.receipt;
    } else {
      this.receipt = this.appDataService.receipt;
    }
  }

  formatted_receipt(receipt: any) {
    if (!receipt || receipt.length !== 16) {
      return "";
    }
    return receipt.slice(0, 4) + " " + receipt.slice(4, 4) + " " + receipt.slice(8, 4) + " " + receipt.slice(12, 4);
  }
}
