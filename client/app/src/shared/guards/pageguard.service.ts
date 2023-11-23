import {Injectable} from "@angular/core";
import {ActivatedRoute, ActivatedRouteSnapshot, Router, RouterStateSnapshot, UrlTree} from "@angular/router";
import {Observable} from "rxjs";
import {AppDataService} from "@app/app-data.service";
import {AuthenticationService} from "@app/services/authentication.service";

@Injectable({
  providedIn: "root"
})
export class Pageguard  {
  constructor(private authenticationService: AuthenticationService, private router: Router, private appDataService: AppDataService) {
  }

  canActivate(next: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean | UrlTree> | Promise<boolean | UrlTree> | boolean | UrlTree {

    if(state.url == "/login"){
      if(this.authenticationService.session && this.authenticationService.session.homepage){
        this.router.navigate([this.authenticationService.session.homepage]).then();
      }
    }else if(state.url == "/"){
      if (this.appDataService.public.node && this.appDataService.public.node.enable_signup) {
        this.router.navigate(["/signup"]).then();
      }
    }else if(state.url == "/submission"){
      if (this.appDataService.public.node && this.appDataService.public.node.enable_signup) {
        this.router.navigate(["/signup"]).then();
      }
    }
    return true;
  }
}
