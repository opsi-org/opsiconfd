# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.product_dependency
"""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.exceptions import OpsiProductOrderingError
from opsicommon.objects import (  # type: ignore[import]
	LocalbootProduct,
	Product,
	ProductDependency,
	ProductOnClient,
)
from opsicommon.types import (  # type: ignore[import]
	forceBool,
	forceInt,
	forceList,
	forceObjectClass,
)

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


def add_action_request(  # pylint: disable=too-many-branches,too-many-statements
	product_on_client_by_product_id: dict[str, ProductOnClient],
	product_id: str,
	product_dependencies_by_product_id: dict[str, list[ProductDependency]],
	available_products_by_product_id: dict[str, Product],
	added_info: dict[str, dict[str, str | None]] | None = None,
) -> None:
	logger.debug("Checking dependencies for product %s, action %s", product_id, product_on_client_by_product_id[product_id].actionRequest)
	added_info = added_info or {}

	poc = product_on_client_by_product_id[product_id]
	if poc.actionRequest == "none" or not product_dependencies_by_product_id.get(product_id):
		return

	for dependency in product_dependencies_by_product_id[product_id]:
		if dependency.productAction != poc.actionRequest:
			continue

		logger.debug("   need to check dependency to product %s", dependency.requiredProductId)
		if dependency.requiredAction:
			logger.debug(
				"   product %s requires action %s of product %s %s-%s on action %s",
				product_id,
				dependency.requiredAction,
				dependency.requiredProductId,
				dependency.requiredProductVersion,
				dependency.requiredPackageVersion,
				dependency.productAction,
			)
		elif dependency.requiredInstallationStatus:
			logger.debug(
				"   product %s requires status %s of product %s %s-%s on action %s",
				product_id,
				dependency.requiredInstallationStatus,
				dependency.requiredProductId,
				dependency.requiredProductVersion,
				dependency.requiredPackageVersion,
				dependency.productAction,
			)

		required_action = dependency.requiredAction
		installation_status: str | None = "not_installed"
		action_request: str | None = "none"
		if dependency.requiredProductId in product_on_client_by_product_id:
			installation_status = product_on_client_by_product_id[dependency.requiredProductId].installationStatus
			action_request = product_on_client_by_product_id[dependency.requiredProductId].actionRequest
		logger.debug("addActionRequest: requiredAction %s", required_action)
		if not required_action:
			if dependency.requiredInstallationStatus == installation_status:
				logger.debug("   required installation status %s is fulfilled", dependency.requiredInstallationStatus)
				continue

			if dependency.requiredInstallationStatus == "installed":
				required_action = "setup"
			elif dependency.requiredInstallationStatus == "not_installed":
				required_action = "uninstall"

		# An action is required => check if possible
		logger.debug("   need to set action %s for product %s to fulfill dependency", required_action, dependency.requiredProductId)

		set_action_request_to_none = False
		if dependency.requiredProductId not in available_products_by_product_id:
			logger.warning(
				"   product %s defines dependency to product %s, which is not avaliable on depot", product_id, dependency.requiredProductId
			)
			set_action_request_to_none = True
		elif (
			dependency.requiredProductVersion is not None
			and dependency.requiredProductVersion != available_products_by_product_id[dependency.requiredProductId].productVersion
		):
			logger.warning(
				"   product %s defines dependency to product %s, but product version %s is not available",
				product_id,
				dependency.requiredProductId,
				dependency.requiredProductVersion,
			)
			set_action_request_to_none = True
		elif (
			dependency.requiredPackageVersion is not None
			and dependency.requiredPackageVersion != available_products_by_product_id[dependency.requiredProductId].packageVersion
		):
			logger.warning(
				"   product %s defines dependency to product %s, but package version %s is not available",
				product_id,
				dependency.requiredProductId,
				dependency.requiredProductId,
			)
			set_action_request_to_none = True

		if set_action_request_to_none:
			logger.notice("   => setting action request for product %s to 'none'!", product_id)
			product_on_client_by_product_id[product_id].actionRequest = "none"
			continue

		if action_request == required_action:
			logger.debug("   => required action %s is already set", required_action)
			continue

		if action_request not in (None, "none"):
			logger.debug(
				"   => cannot fulfill dependency of product %s to product %s: action %s needed but action %s already set",
				product_id,
				dependency.requiredProductId,
				required_action,
				action_request,
			)
			continue

		if dependency.requiredProductId in added_info:
			logger.warning("   => Product dependency loop including product %s detected, skipping", product_id)
			logger.debug(
				"Circular dependency at %s. Processed product: %s addedInfo: %s", dependency.requiredProductId, product_id, added_info
			)
			continue

		logger.info("   => adding action %s for product %s", required_action, dependency.requiredProductId)

		if dependency.requiredProductId not in product_on_client_by_product_id:
			product_on_client_by_product_id[dependency.requiredProductId] = ProductOnClient(
				productId=dependency.requiredProductId,
				productType=available_products_by_product_id[dependency.requiredProductId].getType(),
				clientId=poc.clientId,
				installationStatus=None,
				actionRequest="none",
			)

		assert required_action

		added_info[dependency.requiredProductId] = {
			"addedForProduct": product_id,
			"requiredAction": required_action,
			"requirementType": dependency.requirementType,
		}
		product_on_client_by_product_id[dependency.requiredProductId].setActionRequest(required_action)

		add_action_request(
			product_on_client_by_product_id,
			dependency.requiredProductId,
			product_dependencies_by_product_id,
			available_products_by_product_id,
			added_info,
		)


def add_dependent_product_on_clients(
	product_on_clients: list[ProductOnClient], available_products: list[Product], product_dependencies: list[ProductDependency]
) -> list[ProductOnClient]:
	available_products_by_product_id = {available_product.id: available_product for available_product in available_products}

	product_dependencies_by_product_id = defaultdict(list)
	for product_dependency in product_dependencies:
		product_dependencies_by_product_id[product_dependency.productId].append(product_dependency)

	pocs_by_client_id_and_product_id: dict[str, dict[str, ProductOnClient]] = defaultdict(dict)
	for product_on_client in product_on_clients:
		pocs_by_client_id_and_product_id[product_on_client.clientId][product_on_client.productId] = product_on_client

	dependend_product_on_clients = []
	for client_id, product_on_client_by_product_id in pocs_by_client_id_and_product_id.items():
		logger.debug("Adding dependent productOnClients for client %s", client_id)

		added_info: dict[str, dict[str, str | None]] = {}
		for product_id in list(product_on_client_by_product_id):
			add_action_request(
				product_on_client_by_product_id,
				product_id,
				product_dependencies_by_product_id,
				available_products_by_product_id,
				added_info,
			)
		dependend_product_on_clients.extend(list(product_on_client_by_product_id.values()))

	return dependend_product_on_clients


class XClassifiedProduct:
	"""
	has String member id, int members priority, revised_priority, and a member that is intendend to be a reference to a Product
	"""

	def __init__(self, product: Product) -> None:
		self.id = product.id  # pylint: disable=invalid-name
		self.priority: int = product.priority or 0  # handle this variable as final
		self.revised_priority: int = product.priority or 0  # start value which may be modified
		self.product = product  # keep pointer to the original standard product structure

	def __str__(self) -> str:
		return f"<{self.__class__.__name__}(productId={self.id}, priority={self.priority}, revised_priority={self.revised_priority})>"

	def __repr__(self) -> str:
		return self.__str__()


class OrderRequirement:
	"""
	Represents a request for ordering of two elements with a notice
	if it is fulfilled.
	"""

	def __init__(self, prior: int, posterior: int, fulfilled: bool = False) -> None:
		self.prior = forceInt(prior)
		self.posterior = forceInt(posterior)
		self.fulfilled = forceBool(fulfilled)

	def __str__(self) -> str:
		return f"<OrderRequirement(prior={self.prior!r}, posterior={self.posterior!r}, fulfilled={self.fulfilled!r}>"

	def __repr__(self) -> str:
		return self.__str__()


class Requirements:
	"""Comprises a list with ordering requirements and ordered lists of them"""

	def __init__(self) -> None:
		self.list: list[OrderRequirement] = []
		self.order_by_prior: list[int] = []
		self.order_by_posterior: list[int] = []

	def add(self, requirement: OrderRequirement) -> None:
		assert isinstance(requirement, OrderRequirement), "not an OrderRequirement"
		self.list.append(requirement)
		# Extend the other lists by dummy valuesnoInListOrderedByPriors
		self.order_by_prior.append(-1)
		self.order_by_posterior.append(-1)
		logger.trace("Length of list: %s", len(self.list))
		logger.trace("Length of orderByPrior: %s", len(self.order_by_prior))

		# Continue building the transform map of list indices
		# such that the transformed list is ordered by its prior values
		# therefore:
		#  Determine first the place of the added item
		#  in the ordered sequence i -> list[orderByPrior[i]]
		#  then fix orderByPrior such that it gets this place
		i = 0
		located = False
		while (i < len(self.list) - 1) and not located:
			logger.trace(
				"Requirement.prior: %s, self.list[self.orderByPrior[i]].prior: %s",
				requirement.prior,
				self.list[self.order_by_prior[i]].prior,
			)
			if requirement.prior > self.list[self.order_by_prior[i]].prior:
				i += 1
			else:
				located = True
				# we take the first place that fits to the ordering
				# shift all items by one place
				j = len(self.list) - 1
				while j > i:
					self.order_by_prior[j] = self.order_by_prior[j - 1]
					j -= 1
				# finally we map place i to the new element
				self.order_by_prior[i] = len(self.list) - 1

		if not located:
			# noInListOrderedByPriors
			# if i = len(self.list) - 1 nothing is moved
			self.order_by_prior[i] = len(self.list) - 1

		logger.trace("Set orderByPrior[%s] = %s", i, (len(self.list) - 1))

		# The analogous procedure to get a transformation
		# i -> orderByPosterior[i] such that the sequence
		# i ->  self.list[orderByPosterior[i]]
		# is ordered by the posterior values

		i = 0
		located = False
		while (i < len(self.list) - 1) and not located:
			logger.trace(
				"Requirement.posterior %s, self.list[self.orderByPosterior[i]].posterior) %s",
				requirement.posterior,
				self.list[self.order_by_posterior[i]].posterior,
			)
			if requirement.posterior > self.list[self.order_by_posterior[i]].posterior:
				i += 1
			else:
				located = True
				# We take the first place that fits to the ordering
				# shift all items by one place
				j = len(self.list) - 1
				while j > i:
					self.order_by_posterior[j] = self.order_by_posterior[j - 1]
					j -= 1
				# Finally we map place i to the new element
				self.order_by_posterior[i] = len(self.list) - 1

		if not located:
			# If i = len(self.list) - 1 nothing is moved
			self.order_by_posterior[i] = len(self.list) - 1

	def posterior_index_of(self, posti: int) -> int:
		"""Searches first occurrence of posti as posterior value in the posterior-ordered sequence of requirements"""

		j = 0
		searching = True
		candidate = None
		while (j < len(self.list)) and searching:
			candidate = self.list[self.order_by_posterior[j]]
			if candidate.fulfilled or (candidate.posterior < posti):
				j += 1
			else:
				searching = False

		if searching:
			# All candidates were less than the comparevalue or were not to be regarded any more
			return -1

		# Candidate is not fulfilled and has posterior value >= posti
		if candidate and candidate.posterior == posti:
			return j

		# There are no more possible occurrences of posterior
		return -1

	def index_of_first_not_fulfilled_requirement_ordered_by_prior(self) -> int:
		i = 0
		found = False
		while not found and (i < len(self.list)):
			if self.list[self.order_by_prior[i]].fulfilled:
				i += 1
			else:
				found = True

		if found:
			return i

		return -1

	def first_prior_not_occurring_as_posterior(self, start_idx: int) -> tuple[Any, int]:
		j = start_idx
		found = False
		candidate = self.list[self.order_by_prior[start_idx]].prior
		lastcandidate = -1
		candidates_causing_problemes = []

		while (j < len(self.list)) and not found:
			if not self.list[self.order_by_prior[j]].fulfilled and self.posterior_index_of(candidate) == -1:
				# If requ j still not fulfilled and candidate does not occur
				# as posterior among the not fulfilled
				# then we adopt candidate (i.e. the prior element of requ j in requ list ordered by priors)
				# as next element in our ordered sequence
				found = True
			else:
				if (self.posterior_index_of(candidate) > -1) and (lastcandidate != candidate):
					candidates_causing_problemes.append(candidate)
					lastcandidate = candidate

				# Go on searching
				j += 1
				if j < len(self.list):
					candidate = self.list[self.order_by_prior[j]].prior

		if found:
			no_in_list_ordered_by_priors = j
			return (candidate, no_in_list_ordered_by_priors)

		error_message = f"Potentially conflicting requirements for: {candidates_causing_problemes}"
		logger.error(error_message)
		raise OpsiProductOrderingError(error_message, candidates_causing_problemes)

	def get_count(self) -> int:
		return len(self.list)

	def get_requ_list(self) -> list[OrderRequirement]:
		return self.list

	def get_order_by_prior(self) -> list[int]:
		return self.order_by_prior

	def get_order_by_posteriors(self) -> list[int]:
		return self.order_by_posterior


class OrderBuild:  # pylint: disable=too-many-instance-attributes
	"""Describes the building of an ordering"""

	def __init__(self, element_count: int, requs: Requirements, completing: bool) -> None:
		self.ordering: list[int] = []
		self.element_count = element_count
		self.completing = completing
		self.error_found = False
		self.all_fulfilled = False

		assert isinstance(requs, Requirements), "Expected instance of Requirements"

		self.requs = requs
		self.index_is_among_posteriors = []
		idx = 0
		while idx < element_count:
			self.index_is_among_posteriors.append(False)
			idx += 1

		self.index_used = []
		idx = 0
		while idx < element_count:
			self.index_used.append(False)
			idx += 1

		self.used_count = 0
		logger.trace("OrderBuild initialized")

	def proceed(self) -> bool:  # pylint: disable=too-many-branches
		result = True
		last_sorted_count = 0

		if self.used_count >= self.element_count:
			return result

		index_requ_to_fulfill = self.requs.index_of_first_not_fulfilled_requirement_ordered_by_prior()
		if index_requ_to_fulfill == -1:
			self.all_fulfilled = True
			# Get the posteriors that did not occur as priors
			idx = 0
			while idx < self.element_count:
				if self.index_is_among_posteriors[idx] and not self.index_used[idx]:
					self.ordering.append(idx)
					self.index_used[idx] = True
					self.used_count += 1
				idx += 1
			last_sorted_count = self.used_count

			if self.completing:
				# Take rest from list
				idx = 0
				while idx < self.element_count:
					if not self.index_used[idx]:
						self.ordering.append(idx)
						self.index_used[idx] = True
						self.used_count += 1
					idx += 1

				# Move the sorted items to the end of the list
				if last_sorted_count > 0:
					newordering = []
					k = 0
					while k < self.element_count:
						newordering.append(k)
						k += 1

					# Rearrange not sorted elements
					for k in range(self.element_count - last_sorted_count):
						newordering[k] = self.ordering[last_sorted_count + k]

					# Sorted elements
					for k in range(last_sorted_count):
						newordering[self.element_count - last_sorted_count + k] = self.ordering[k]

					# Put back
					self.ordering = newordering
		else:
			# At indexRequToFulfill we found a not fulfilled requirement,
			# lets try to fulfill a requirement
			# look only at not fulfilled reqirements
			# Find the first one, in ordering by priors, with the
			# property that it does not occur as posterior
			# take it as new_entry for the ordered list
			# Automatically any requirement is fulfilled where newEntry
			# is the prior; do the markings

			(new_entry, requ_no_in_list_ordered_by_priors) = self.requs.first_prior_not_occurring_as_posterior(index_requ_to_fulfill)

			if new_entry == -1:
				result = False
			else:
				self.ordering.append(new_entry)
				self.used_count += 1
				# Mark all requirements with candidate in prior position
				# as fulfilled and collect the posteriors
				k = requ_no_in_list_ordered_by_priors
				order_by_prior = self.requs.get_order_by_prior()
				requ_k = self.requs.get_requ_list()[order_by_prior[k]]
				while (k < self.requs.get_count()) and (new_entry == requ_k.prior):
					requ_k.fulfilled = True
					self.index_is_among_posteriors[requ_k.posterior] = True
					k += 1
					if k < self.requs.get_count():
						requ_k = self.requs.get_requ_list()[order_by_prior[k]]
				self.index_used[new_entry] = True

			logger.debug("proceed new_entry %s", new_entry)

		logger.debug("proceed result %s", result)
		return result

	def get_ordering(self) -> list[int]:
		return self.ordering


def get_requirements(product_dependencies: list[ProductDependency], uninstall: bool = False) -> list[tuple[str, str]]:
	# Requirements are list of pairs (install_prior, install_posterior)
	# We treat setup an uninstall requirements only
	requirements = []
	for dependency in product_dependencies:
		if dependency.productAction not in ("setup", "uninstall") if uninstall else ("setup",):
			continue
		if dependency.requiredInstallationStatus not in ("not_installed", "installed") and dependency.requiredAction not in (
			"setup",
			"uninstall",
		):
			continue

		if dependency.requiredInstallationStatus and dependency.requiredAction:
			raise OpsiProductOrderingError(f"{dependency} defines requiredInstallationStatus and requiredAction")

		if dependency.requirementType == "before":
			requirements.append((dependency.requiredProductId, dependency.productId))
		elif dependency.requirementType == "after":
			requirements.append((dependency.productId, dependency.requiredProductId))

	return requirements


def generate_product_sequence(available_products: list[Product], product_dependencies: list[ProductDependency]) -> list[str]:
	logger.info("Generating product sequence")
	requirements = get_requirements(product_dependencies, uninstall=False)
	return generate_product_sequence_from_requ_pairs(available_products, requirements)


def modify_sorting_classes(  # pylint: disable=too-many-branches
	products: list[XClassifiedProduct], setup_requirements: list[tuple[str, str]]
) -> bool:
	recursion_necessary = False

	f_id_to_prod = {prod.id: prod for prod in products}
	# state of priorityClasses
	f_level_to_prodlist: dict[int, list[XClassifiedProduct]] = {level: [] for level in reversed(range(-100, 101))}
	for prod in products:
		f_level_to_prodlist[prod.revised_priority].append(prod)

	requs_by_posterior: dict[str, list[tuple[str, str]]] = {}
	for requ in setup_requirements:
		if requ[1] not in requs_by_posterior:
			requs_by_posterior[requ[1]] = []

		requs_by_posterior[requ[1]].append(requ)

	for level in range(-100, 101):  # pylint: disable=too-many-nested-blocks
		logger.trace("We are about to correct level %s...", level)
		if not f_level_to_prodlist[level]:
			logger.trace("no elements in this level")
			continue

		for posti in f_level_to_prodlist[level]:
			logger.trace("posti %s", posti)
			if posti.id in requs_by_posterior:
				remove_requs = []
				for requ in requs_by_posterior[posti.id]:
					if requ[0] not in f_id_to_prod:
						logger.debug("product %s should be arranged before product %s but is not available", requ[0], requ[1])
						remove_requs.append(requ)
					else:
						if f_id_to_prod[requ[0]].revised_priority < level:
							logger.debug(
								"product %s must be pushed upwards from level %s to level %s, the level of %s,"
								" to meet the requirement first %s, later %s",
								requ[0],
								f_id_to_prod[requ[0]].revised_priority,
								level,
								posti.id,
								requ[0],
								requ[1],
							)
							f_id_to_prod[requ[0]].revised_priority = level
							recursion_necessary = True

				for requ in remove_requs:
					requs_by_posterior[posti.id].remove(requ)

	return recursion_necessary


def generate_product_sequence_from_requ_pairs(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	available_products: list[Product], setup_requirements: list[tuple[str, str]]
) -> list[str]:
	"""Returns sorted list of prduct ids"""
	logger.debug("available products %s", available_products)

	available_x_products = [XClassifiedProduct(product) for product in available_products]

	requs_by_posterior: dict[str, list[tuple[str, str]]] = {}
	for requ in setup_requirements:
		if requ[1] not in requs_by_posterior:
			requs_by_posterior[requ[1]] = []

		requs_by_posterior[requ[1]].append(requ)

	# Recursively modify the priority levels.
	# We move prods upwards as long as there are movements necessary.
	# The algorithm halts since the moves are only upwards and are bounded
	ready = False
	while not ready:
		ready = not modify_sorting_classes(available_x_products, setup_requirements)
		if ready:
			logger.debug("Recursion finished")
		else:
			logger.debug("Was modified, step to next recursion")

	# We map xProduct onto Product
	for product in available_x_products:
		product.priority = product.revised_priority

	product_ids = []
	priority_classes = defaultdict(list)
	product_index_in_class = {}
	product_by_id = {}
	for product in available_x_products:
		product_ids.append(product.id)
		product_by_id[product.id] = product
		prio = "0"
		if product.priority:
			prio = str(product.priority)

		priority_classes[prio].append(product.id)
		product_index_in_class[product.id] = len(priority_classes[prio]) - 1

	logger.debug("productIndexInClass %s", product_index_in_class)
	logger.debug("priorityClasses %s", priority_classes)

	requirements_by_classes = defaultdict(list)

	for prod1, prod2 in setup_requirements:
		logger.debug("First product: %s", prod1)
		if prod1 not in product_by_id:
			logger.debug("Product %s is requested but not available", prod1)
			continue

		logger.debug("Second product: %s", prod2)
		if prod2 not in product_by_id:
			logger.debug("Product %s is requested but not available", prod2)
			continue

		prio1 = product_by_id[prod1].priority or 0
		prio2 = product_by_id[prod2].priority or 0

		logger.debug("Priority %s: %s", prod1, prio1)
		logger.debug("Priority %s: %s", prod2, prio2)
		if prio1 > prio2:
			logger.debug("The ordering is guaranteed by priority handling")
		elif prio1 < prio2:
			logger.warning("Dependency declaration between %s and %s contradicts priority declaration, will be ignored", prod1, prod2)
		else:
			prioclasskey = str(prio1)
			requirements_by_classes[prioclasskey].append([product_index_in_class[prod1], product_index_in_class[prod2]])

	found_classes = []
	orderings_by_classes = {}
	sorted_list: list[str] = []
	order_build = None
	try:
		for priority in reversed(range(-100, 101)):
			prioclasskey = str(priority)
			if prioclasskey not in priority_classes:
				continue
			found_classes.append(prioclasskey)
			prioclass = priority_classes[prioclasskey]

			if prioclasskey in requirements_by_classes:
				requs = requirements_by_classes[prioclasskey]
				requ_objects = Requirements()
				for item in requs:
					requ_objects.add(OrderRequirement(item[0], item[1], False))

				order_build = OrderBuild(len(prioclass), requ_objects, True)
				try:
					for _ in prioclass:
						order_build.proceed()
				except OpsiProductOrderingError as err:
					logger.warning("Product sort algorithm caught OpsiProductOrderingError: %s", err)
					for idx, prio in enumerate(prioclass):
						logger.info(" product %s %s", idx, prio)

					raise OpsiProductOrderingError(
						"Potentially conflicting requirements for: "
						f"{', '.join([prioclass[int(index)] for index in err.problematicRequirements])}"
					) from err

				orderings_by_classes[prioclasskey] = order_build.get_ordering()
				logger.debug("prioclasskey, ordering %s, %s", prioclasskey, order_build.get_ordering())

		for prioclasskey in found_classes:
			prioclass = priority_classes[prioclasskey]
			logger.debug("prioclasskey has prioclass %s, %s", prioclasskey, prioclass)
			if prioclasskey in orderings_by_classes:
				ordering = orderings_by_classes[prioclasskey]
				assert order_build
				logger.debug("prioclasskey in found classes, ordering %s, %s", prioclasskey, order_build.get_ordering())

				sorted_list += [prioclass[idx] for idx in ordering]
			else:
				sorted_list += prioclass

		logger.debug("sorted_list: %s", sorted_list)
	except OpsiProductOrderingError as err:
		logger.error(err, exc_info=True)
		raise

	return sorted_list


def generate_product_on_client_sequence(
	product_on_clients: list[ProductOnClient], available_products: list[Product], product_dependencies: list[ProductDependency]
) -> list[ProductOnClient]:
	logger.info("Generating productOnClient sequence")
	requirements = get_requirements(product_dependencies, uninstall=True)
	sorted_product_list = generate_product_sequence_from_requ_pairs(available_products, requirements)

	pocs_by_client_id_and_product_id: dict[str, dict[str, ProductOnClient]] = defaultdict(dict)
	for product_on_client in product_on_clients:
		pocs_by_client_id_and_product_id[product_on_client.clientId][product_on_client.productId] = product_on_client

	product_on_clients = []
	for product_on_clients_by_product_id in pocs_by_client_id_and_product_id.values():
		sequence = 0
		for product_id in sorted_product_list:
			if product_id in product_on_clients_by_product_id:
				product_on_clients_by_product_id[product_id].actionSequence = sequence
				product_on_clients.append(product_on_clients_by_product_id[product_id])
				del product_on_clients_by_product_id[product_id]
				sequence += 1

		if sorted_product_list:
			logger.debug("Handle remaining if existing")
			for product_id in product_on_clients_by_product_id.keys():
				product_on_clients_by_product_id[product_id].actionSequence = sequence
				product_on_clients.append(product_on_clients_by_product_id[product_id])
				sequence += 1

	return product_on_clients


class RPCProductDependencyMixin(Protocol):
	def productDependency_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependencies: list[dict] | list[ProductDependency]  # pylint: disable=invalid-name
	) -> None:
		self._mysql.bulk_insert_objects(table="PRODUCT_DEPENDENCY", objs=productDependencies)  # type: ignore[arg-type]

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependency: dict | ProductDependency  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productDependency_insertObject")
		productDependency = forceObjectClass(productDependency, ProductDependency)
		self._mysql.insert_object(table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependency: dict | ProductDependency  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productDependency_updateObject")
		productDependency = forceObjectClass(productDependency, ProductDependency)
		self._mysql.insert_object(table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productDependency_createObjects")
		with self._mysql.session() as session:
			for productDependency in forceList(productDependencies):
				productDependency = forceObjectClass(productDependency, ProductDependency)
				self._mysql.insert_object(
					table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=True, set_null=True, session=session
				)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("productDependency_updateObjects")
		with self._mysql.session() as session:
			for productDependency in forceList(productDependencies):
				productDependency = forceObjectClass(productDependency, ProductDependency)
				self._mysql.insert_object(
					table="PRODUCT_DEPENDENCY", obj=productDependency, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def productDependency_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[ProductDependency]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_DEPENDENCY", ace=ace, object_type=ProductDependency, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productDependency_getHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[dict]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_objects(
			table="PRODUCT_DEPENDENCY", object_type=ProductDependency, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def productDependency_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("productDependency_getObjects")
		return self._mysql.get_idents(
			table="PRODUCT_DEPENDENCY", object_type=ProductDependency, ace=ace, ident_type=returnType, filter=filter
		)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, productDependencies: list[dict] | list[ProductDependency] | dict | ProductDependency
	) -> None:
		if not productDependencies:
			return
		ace = self._get_ace("productDependency_deleteObjects")
		self._mysql.delete_objects(table="PRODUCT_DEPENDENCY", object_type=ProductDependency, obj=productDependencies, ace=ace)

	@rpc_method(check_acl=False, clear_cache="product_ordering")
	def productDependency_create(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		productId: str,  # pylint: disable=unused-argument
		productVersion: str,  # pylint: disable=unused-argument
		packageVersion: str,  # pylint: disable=unused-argument
		productAction: str,  # pylint: disable=unused-argument
		requiredProductId: str | None = None,  # pylint: disable=unused-argument
		requiredProductVersion: str | None = None,  # pylint: disable=unused-argument
		requiredPackageVersion: str | None = None,  # pylint: disable=unused-argument
		requiredAction: str | None = None,  # pylint: disable=unused-argument
		requiredInstallationStatus: str | None = None,  # pylint: disable=unused-argument
		requirementType: str | None = None,  # pylint: disable=unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.productDependency_createObjects(ProductDependency.fromHash(_hash))

	@rpc_method(check_acl=False)
	def productDependency_delete(  # pylint: disable=redefined-builtin,invalid-name,too-many-arguments
		self: BackendProtocol,
		productId: list[str] | str,
		productVersion: list[str] | str,
		packageVersion: list[str] | str,
		productAction: list[str] | str,
		requiredProductId: list[str] | str,
	) -> None:
		idents = self.productDependency_getIdents(
			returnType="dict",
			productId=productId,
			productVersion=productVersion,
			packageVersion=packageVersion,
			productAction=productAction,
			requiredProductId=requiredProductId,
		)
		if idents:
			self.productDependency_deleteObjects(idents)

	@rpc_method(check_acl=False, use_cache="product_ordering")
	def getProductOrdering(  # pylint: disable=invalid-name,too-many-branches
		self: BackendProtocol, depotId: str, sortAlgorithm: str | None = None
	) -> dict[str, list]:
		if sortAlgorithm and sortAlgorithm != "algorithm1":
			raise ValueError(f"Invalid sort algorithm {sortAlgorithm!r}")

		products_by_id_and_version: dict[str, dict[str, dict[str, LocalbootProduct]]] = {}
		for product in self.product_getObjects(type="LocalbootProduct"):
			if product.id not in products_by_id_and_version:
				products_by_id_and_version[product.id] = {}
			if product.productVersion not in products_by_id_and_version[product.id]:
				products_by_id_and_version[product.id][product.productVersion] = {}

			products_by_id_and_version[product.id][product.productVersion][product.packageVersion] = product

		products_dependencies_by_id_and_version: dict[str, dict[str, dict[str, list[ProductDependency]]]] = {}
		for prod_dep in self.productDependency_getObjects(productAction="setup"):
			if prod_dep.productId not in products_dependencies_by_id_and_version:
				products_dependencies_by_id_and_version[prod_dep.productId] = {}
			if prod_dep.productVersion not in products_dependencies_by_id_and_version[prod_dep.productId]:
				products_dependencies_by_id_and_version[prod_dep.productId][prod_dep.productVersion] = {}
			if prod_dep.packageVersion not in products_dependencies_by_id_and_version[prod_dep.productId][prod_dep.productVersion]:
				products_dependencies_by_id_and_version[prod_dep.productId][prod_dep.productVersion][prod_dep.packageVersion] = []

			products_dependencies_by_id_and_version[prod_dep.productId][prod_dep.productVersion][prod_dep.packageVersion].append(prod_dep)

		available_products = []
		product_dependencies = []
		product_ids = []
		for product_on_depot in self.productOnDepot_getObjects(depotId=depotId, productType="LocalbootProduct"):
			product = (
				products_by_id_and_version.get(product_on_depot.productId, {})
				.get(product_on_depot.productVersion, {})
				.get(product_on_depot.packageVersion)
			)
			if not product:
				continue
			available_products.append(product)
			product_ids.append(product.id)
			if not product.setupScript:
				continue
			product_dependencies.extend(
				products_dependencies_by_id_and_version.get(product_on_depot.productId, {})
				.get(product_on_depot.productVersion, {})
				.get(product_on_depot.packageVersion, [])
			)

		product_ids.sort()
		sorted_list = generate_product_sequence(available_products, product_dependencies)
		return {"not_sorted": product_ids, "sorted": sorted_list}
