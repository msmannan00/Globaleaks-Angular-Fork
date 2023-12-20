import {Injectable} from "@angular/core";
import { Router, UrlTree } from "@angular/router";
import {Observable} from "rxjs";
import {AuthenticationService} from "@app/services/helper/authentication.service";
import {AppDataService} from "@app/app-data.service";
import {AppConfigService} from "@app/services/root/app-config.service";

@Injectable({
  providedIn: "root"
})
export class ReceiverGuard  {
  constructor(private appConfigService: AppConfigService, private router: Router, private appDataService: AppDataService, public authenticationService: AuthenticationService) {
  }

  canActivate(): Observable<boolean | UrlTree> | Promise<boolean | UrlTree> | boolean | UrlTree {
    if (!this.authenticationService.session || this.authenticationService.session.role !== "receiver") {
      this.router.navigateByUrl("/login").then();
      return false;
    } else {
      this.appConfigService.setPage(this.router.url);
      return true;
    }
  }
}
