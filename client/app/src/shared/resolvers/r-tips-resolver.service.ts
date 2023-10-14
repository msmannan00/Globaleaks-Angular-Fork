import {Injectable} from "@angular/core";
import {Resolve} from "@angular/router";
import {Observable, of} from "rxjs";
import {HttpService} from "@app/shared/services/http.service";
import {AuthenticationService} from "@app/services/authentication.service";
import {map} from "rxjs/operators";
import {rtipResolverModel} from "@app/models/resolvers/rtipsResolverModel";

@Injectable({
  providedIn: "root"
})
export class RTipsResolver implements Resolve<boolean> {
  dataModel: rtipResolverModel[] = [];

  constructor(private httpService: HttpService, private authenticationService: AuthenticationService) {
  }

  resolve(): Observable<boolean> {
    if (this.authenticationService.session.role === "receiver") {
      return this.httpService.receiverTipResource().pipe(
        map((response: any) => {
          console.log(response);
          this.dataModel = response;
          return true;
        })
      );
    }
    return of(true);
  }
}
