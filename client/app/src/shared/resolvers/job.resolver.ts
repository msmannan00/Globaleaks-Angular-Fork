import {Injectable} from "@angular/core";
import {Resolve,} from "@angular/router";
import {Observable, of} from "rxjs";
import {map} from "rxjs/operators";
import {HttpService} from "@app/shared/services/http.service";
import {AuthenticationService} from "@app/services/authentication.service";
import {jobResolverModel} from "@app/models/resolvers/job-resolver-model";

@Injectable({
  providedIn: "root"
})
export class JobResolver implements Resolve<boolean> {
  dataModel: jobResolverModel = new jobResolverModel();

  constructor(private httpService: HttpService, private authenticationService: AuthenticationService) {
  }

  resolve(): Observable<boolean> {
    if (this.authenticationService.session.role === "admin") {
      return this.httpService.requestJobResource().pipe(
        map((response: jobResolverModel) => {
          this.dataModel = response;
          return true;
        })
      );
    }
    return of(true);
  }

}
