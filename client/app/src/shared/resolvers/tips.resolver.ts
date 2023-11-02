import {Injectable} from "@angular/core";
import {Resolve} from "@angular/router";
import {Observable, of} from "rxjs";
import {HttpService} from "@app/shared/services/http.service";
import {AuthenticationService} from "@app/services/authentication.service";
import {tipsResolverModel} from "@app/models/resolvers/tips-resolver-model";
import {map} from "rxjs/operators";

@Injectable({
  providedIn: "root"
})
export class TipsResolver implements Resolve<boolean> {
  dataModel: tipsResolverModel = new tipsResolverModel();

  constructor(private httpService: HttpService, private authenticationService: AuthenticationService) {
  }

  resolve(): Observable<boolean> {
    if (this.authenticationService.session.role === "admin") {
      return this.httpService.requestTipResource().pipe(
        map((response: tipsResolverModel) => {
          this.dataModel = response;
          return true;
        })
      );
    }
    return of(true);
  }

}
