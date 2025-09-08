class CustomDashboardAdvancedFilters:
    '''This class implements the advanced filters feature.

    The `AdvancedFilters` object has the following attributes:
        * `filter_list`: a list of dictionaries containg the filter
        * `query_dump`: dump of the elastic query
        * `custom_dashboard_conditions`: conditions to evaluate weather the
            query is from the custom dashboard module

    '''

    def __init__(self, filter_list, query_dump, custom_dashboard_conditions=None):
        self.filter_list = filter_list
        self.query_dump = query_dump
        self.filter_query = None

        # Conditions to check how to append filters to
        # securityevents queries
        self.custom_dashboard_conditions = custom_dashboard_conditions

    def evaluate_filter_expression(self, **kwargs):
        '''Evaluates the filter expression

        This method evaluates the conditions in the filter dictionary based on the operators
        in `filter_dict`. It iterates through the list of filters and evalutes conditions for
        each filter.

        '''

        # iterating the list of filters
        for filter_dict in self.filter_list:

            if "ignore_cd_status_filter" in kwargs and kwargs["ignore_cd_status_filter"] == True:

                # ignoring filter on status field for vul dashboard
                if filter_dict["field"] == "geoip.geo.country_name":
                    continue

            # Evaluating `is` operator
            if filter_dict["operator"] == 'is':

                # Creating filter clause if it doesnot exists in query dump
                # only necessary for case of queries other than securityevents
                if 'filter' not in self.query_dump["query"]["bool"]:
                    self.query_dump["query"]["bool"]["filter"] = []

                # for sca benchmark filters
                # filter expression is different
                if filter_dict["field"] == "event_type":
                    filter_expression = {"wildcard": {
                        filter_dict["field"]: {"value": filter_dict["value"]+"*"}}}

                # case for all other
                # filters
                else:
                    filter_expression = {"match_phrase": {
                        filter_dict["field"]: filter_dict["value"]}}

                self._append_filter_to_query(filter_expression, "is")

            # Evaluating `is not` operator
            if filter_dict["operator"] == 'is_not':

                # Creating must not clause if it doesnot exists in query dump
                # only necessary for case of queries other than securityevents
                if 'must_not' not in self.query_dump["query"]["bool"]:
                    self.query_dump["query"]["bool"]["must_not"] = []

                filter_expression = {"match_phrase": {
                    filter_dict["field"]: filter_dict["value"]}}
                self._append_filter_to_query(filter_expression, "is_not")

            # Evaluating `is one of` operator
            if filter_dict["operator"] == 'is_one_of':

                # Creating filter clause if it doesnot exists in query dump
                # only necessary for case of queries other than securityevents
                if 'filter' not in self.query_dump["query"]["bool"]:
                    self.query_dump["query"]["bool"]["filter"] = []

                should_clause = []

                for value in filter_dict["value"]:
                    should_clause.append(
                        {"match_phrase": {filter_dict["field"]: value}}
                    )
                filter_expression = {
                    "bool": {"should": should_clause, "minimum_should_match": 1}}
                self._append_filter_to_query(filter_expression, "is_one_of")

            # Evaluating `is_not_one_of` operator
            if filter_dict["operator"] == 'is_not_one_of':

                # Creating must not clause if it doesnot exists in query dump
                # only necessary for case of queries other than securityevents
                if 'must_not' not in self.query_dump["query"]["bool"]:
                    self.query_dump["query"]["bool"]["must_not"] = []

                should_clause = []

                for value in filter_dict["value"]:
                    should_clause.append(
                        {"match_phrase": {filter_dict["field"]: value}}
                    )
                filter_expression = {
                    "bool": {"should": should_clause, "minimum_should_match": 1}}
                self._append_filter_to_query(
                    filter_expression, "is_not_one_of")

            # Evaluating `is between` operator
            if filter_dict["operator"] == 'is_between':

                # Creating filter clause if it doesnot exists in query dump
                # only necessary for case of queries other than securityevents
                if 'filter' not in self.query_dump["query"]["bool"]:
                    self.query_dump["query"]["bool"]["filter"] = []

                # TODO: how will the api recieve the filter range in the `value` key?
                # As a dictionary or as a list?
                filter_expression = {"range": {filter_dict["field"]: {
                    "gte": filter_dict["value"][0], "lt": filter_dict["value"][1]}}}
                self._append_filter_to_query(filter_expression, "is_between")

            # Evaluating `is not between` operator
            if filter_dict["operator"] == 'is_not_between':

                # Creating must not clause if it doesnot exists in query dump
                # only necessary for case of queries other than securityevents
                if 'must_not' not in self.query_dump["query"]["bool"]:
                    self.query_dump["query"]["bool"]["must_not"] = []

                # TODO: how will the api recieve the filter range in the `value` key?
                # As a dictionary or as a list?
                filter_expression = {"range": {filter_dict["field"]: {
                    "gte": filter_dict["value"][0], "lt": filter_dict["value"][1]}}}
                self._append_filter_to_query(
                    filter_expression, "is_not_between")

            # Evaluating `exists` operator
            if filter_dict["operator"] == 'exists':

                # Creating filter clause if it doesnot exists in query dump
                # only necessary for case of queries other than securityevents
                if 'filter' not in self.query_dump["query"]["bool"]:
                    self.query_dump["query"]["bool"]["filter"] = []

                filter_expression = {"exists": {"field": filter_dict["field"]}}
                self._append_filter_to_query(filter_expression, "exists")

            # Evaluating `does_not_exists` operator
            if filter_dict["operator"] == 'does_not_exists':

                # Creating must not clause if it doesnot exists in query dump
                # only necessary for case of queries other than securityevents
                if 'must_not' not in self.query_dump["query"]["bool"]:
                    self.query_dump["query"]["bool"]["must_not"] = []

                filter_expression = {"exists": {"field": filter_dict["field"]}}
                self._append_filter_to_query(
                    filter_expression, "does_not_exists")
    
    def _append_filter_to_query(self, filter_expression, filter_operator):
        '''This method appends the filter expression to the query dump

        Before appending the filter expression to `query_dump`, the method checks for two conditions
            * First `if` is evaluated incase of queries other than NDR queries
            * The `else` block is evaluated incase of queries of NDR. here queries are nested
                to accomodate both agents and agentless devices data
        '''

        if filter_operator in ["is", "is_one_of", "is_between", "exists"]:
            if not self.network_monitoring_conditions:
                self.query_dump["query"]["bool"]["filter"].append(
                    filter_expression)
            else:
                if (not self.network_monitoring_conditions["agents_list"] and not self.network_monitoring_conditions["device_hostnames"]) or self.security_conditions["agents_list"]:
                    self.query_dump['query']['bool']['should'][0]["bool"]["filter"].append(
                        filter_expression)

                if self.network_monitoring_conditions["device_hostnames"] and not self.network_monitoring_conditions["agents_list"]:
                    self.query_dump['query']['bool']['should'][0]["bool"]["filter"].append(
                        filter_expression)

                if self.network_monitoring_conditions["device_hostnames"] and self.network_monitoring_conditions["agents_list"]:
                    self.query_dump['query']['bool']['should'][1]["bool"]["filter"].append(
                        filter_expression)

        if filter_operator in ["is_not", "is_not_one_of", "is_not_between", "does_not_exists"]:
            if not self.network_monitoring_conditions:
                self.query_dump["query"]["bool"]["must_not"].append(
                    filter_expression)
            else:
                if (not self.network_monitoring_conditions["agents_list"] and not self.network_monitoring_conditions["device_hostnames"]) or self.security_conditions["agents_list"]:
                    self.query_dump['query']['bool']['should'][0]["bool"]["must_not"].append(
                        filter_expression)

                if self.network_monitoring_conditions["device_hostnames"] and not self.network_monitoring_conditions["agents_list"]:
                    self.query_dump['query']['bool']['should'][0]["bool"]["must_not"].append(
                        filter_expression)

                if self.network_monitoring_conditions["device_hostnames"] and self.security_conditions["agents_list"]:
                    self.query_dump['query']['bool']['should'][1]["bool"]["must_not"].append(
                        filter_expression)

    def get_filtered_query(self) -> dict:
        '''Returns the updated query with filters applied'''

        return self.query_dump
