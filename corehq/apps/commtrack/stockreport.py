from casexml.apps.case.models import CommCareCase
from casexml.apps.case.tests.util import CaseBlock
from casexml.apps.case.xml import V2
from lxml import etree
from lxml.builder import ElementMaker
from xml import etree as legacy_etree
from datetime import date, timedelta
from receiver.util import spoof_submission
from corehq.apps.receiverwrapper.util import get_submit_url
from dimagi.utils.couch.loosechange import map_reduce
import logging
from corehq.apps.commtrack.models import CommtrackConfig
from corehq.apps.commtrack.requisitions import RequisitionState
from corehq.apps.commtrack import const

logger = logging.getLogger('commtrack.incoming')

XMLNS = 'http://openrosa.org/commtrack/stock_report'
META_XMLNS = 'http://openrosa.org/jr/xforms'
def _(tag, ns=XMLNS):
    return '{%s}%s' % (ns, tag)
def XML(ns=XMLNS, prefix=None):
    prefix_map = None
    if prefix:
        prefix_map = {prefix: ns}
    return ElementMaker(namespace=ns, nsmap=prefix_map)

def process(domain, instance):
    """process an incoming commtrack stock report instance"""
    config = CommtrackConfig.for_domain(domain)
    root = etree.fromstring(instance)
    user_id, transactions = unpack_transactions(root, config)

    case_ids = [tx.case_id for tx in transactions]
    cases = dict((c._id, c) for c in CommCareCase.view('_all_docs', keys=case_ids, include_docs=True))

    def get_transactions(all_tx, type_filter):
        """get all the transactions of the relevant type (filtered by type_filter),
        grouped by product (returns a dict of 'product subcase id' => list of transactions),
        with each set of transactions sorted in the correct order for processing
        """
        return map_reduce(lambda tx: [(tx.case_id,)],
                          lambda v: sorted(v, key=lambda tx: tx.priority_order), # important!
                          data=filter(type_filter, all_tx),
                          include_docs=True)

    # split transactions by type and product
    stock_transactions = get_transactions(transactions, lambda tx: tx.category == 'stock')
    requisition_transactions = get_transactions(transactions, lambda tx: tx.category == 'requisition')

    # TODO: code to auto generate / update requisitions from transactions if
    # project is configured for that.

    post_processed_transactions = list(transactions)
    for product_id, product_case in cases.iteritems():
        stock_txs = stock_transactions.get(product_id, [])
        if stock_txs:
            case_block, reconciliations = process_product_transactions(user_id, product_case, stock_txs)
            root.append(case_block)
            post_processed_transactions.extend(reconciliations)

        req_txs = requisition_transactions.get(product_id, [])
        if req_txs and config.requisitions_enabled:
            req = RequisitionState.from_transactions(user_id, product_case, req_txs)
            case_block = etree.fromstring(req.to_xml())
            root.append(case_block)
    replace_transactions(root, post_processed_transactions)

    submission = etree.tostring(root)
    logger.debug('submitting: %s' % submission)

    submit_time = root.find('.//%s' % _('timeStart', META_XMLNS)).text
    spoof_submission(get_submit_url(domain), submission, headers={'HTTP_X_SUBMIT_TIME': submit_time}, hqsubmission=False)



class StockTransaction(object):
    def __init__(self, **kwargs):
        self.product = kwargs.get('product')
        self.product_id = kwargs.get('product_id') or self.product._id
        self.action_name = kwargs['action_name']
        self.value = kwargs['value']
        self.case_id = kwargs.get('case_id') or kwargs.get('get_caseid', lambda p: None)(self.product_id)
        self.inferred = kwargs.get('inferred', False)
        self.processing_order = kwargs.get('order')

        self.config = kwargs.get('config')
        if self.config:
            self.action_config = self.config.all_actions_by_name[self.action_name]
            self.priority_order = [action.action_name for action in self.config.all_actions()].index(self.action_name)

        assert self.product_id
        assert self.case_id

    @property
    def base_action_type(self):
        return self.action_config.action_type

    @classmethod
    def from_xml(cls, tx, config=None):
        data = {
            'product_id': tx.find(_('product')).text,
            'case_id': tx.find(_('product_entry')).text,
            'value': int(tx.find(_('value')).text),
            'inferred': tx.attrib.get('inferred') == 'true',
            'action_name': tx.find(_('action')).text,
        }
        return cls(config=config, **data)

    def to_xml(self, E=None, **kwargs):
        if not E:
            E = XML()

        attr = {}
        if self.inferred:
            attr['inferred'] = 'true'
        if self.processing_order is not None:
            attr['order'] = str(self.processing_order + 1)

        return E.transaction(
            E.product(self.product_id),
            E.product_entry(self.case_id),
            E.action(self.action_name),
            E.value(str(self.value)),
            **attr
        )

    @property
    def category(self):
        return 'stock'

    def __repr__(self):
        return '{action}: {value} (case: {case}, product: {product})'.format(
            action=self.action_name, value=self.value, case=self.case_id,
            product=self.product_id
        )

class Requisition(StockTransaction):
    @property
    def category(self):
        return 'requisition'

    @classmethod
    def from_xml(cls, tx, config=None):
        data = {
            'product_id': tx.find(_('product')).text,
            'case_id': tx.find(_('product_entry')).text,
            'value': int(tx.find(_('value')).text),
            'action_name': 'request',
        }
        return cls(config=config, **data)

    def to_xml(self, E=None, **kwargs):
        if not E:
            E = XML()

        return E.request(
            E.product(self.product_id),
            E.product_entry(self.case_id),
            E.value(str(self.value)),
        )

class RequisitionResponse(object):
    def __init__(self, action_name):
        self.action_name = action_name

    @property
    def category(self):
        return 'requisition'

    @property
    def product_id(self):
        return const.ALL_PRODUCTS_TRANSACTION_TAG

    @classmethod
    def from_xml(cls, tx, config=None):
        data = {
            'action_name': tx.find(_('status')).text,
        }
        return cls(**data)

    def to_xml(self, E=None, **kwargs):
        if not E:
            E = XML()

        return E.response(
            E.status(self.action_name),
            E.product(self.product_id),
        )

def unpack_transactions(root, config):
    user_id = root.find('.//%s' % _('userID', META_XMLNS)).text
    def transactions():
        types = {
            'transaction': StockTransaction,
            'request': Requisition,
            'response': RequisitionResponse,
        }
        for tag, factory in types.iteritems():
            for tx in root.findall(_(tag)):
                yield factory.from_xml(tx, config)

    return user_id, list(transactions())

def replace_transactions(root, new_tx):
    for tag in ('transaction', 'request', 'response'):
        for tx in root.findall(_(tag)):
            tx.getparent().remove(tx)
    for tx in new_tx:
        root.append(tx.to_xml())

def process_product_transactions(user_id, case, txs):
    """process all the transactions from a stock report for an individual
    product. we have to apply them in bulk because each one may update
    the case state that the next one works off of. therefore we have to
    keep track of the updated case state ourselves
    """
    current_state = StockState(case)
    reconciliations = []

    i = [0] # annoying python 2.x scope issue
    def set_order(tx):
        tx.processing_order = i[0]
        i[0] += 1

    for tx in txs:
        recon = current_state.update(tx.base_action_type, tx.value)
        if recon:
            set_order(recon)
            reconciliations.append(recon)
        set_order(tx)
    return current_state.to_case_block(user_id=user_id), reconciliations

class StockState(object):
    def __init__(self, case):
        self.case = case
        props = case.dynamic_properties()
        self.current_stock = int(props.get('current_stock', 0)) # int
        self.stocked_out_since = props.get('stocked_out_since') # date

    def update(self, action_type, value):
        """given the current stock state for a product at a location, update
        with the incoming datapoint
        
        fancy business logic to reconcile stock reports lives HERE
        """
        reconciliation_transaction = None
        def mk_reconciliation(diff):
            return StockTransaction(
                product_id=self.case.product,
                case_id=self.case._id,
                action_name='receipts' if diff > 0 else 'consumption', # TODO argh, these are base actions, not config actions
                value=abs(diff),
                inferred=True,
            )

        if action_type == 'stockout' or (action_type == 'stockedoutfor' and value > 0):
            if self.current_stock > 0:
                reconciliation_transaction = mk_reconciliation(-self.current_stock)

            self.current_stock = 0
            days_stocked_out = (value - 1) if action_type == 'stockedoutfor' else 0
            self.stocked_out_since = date.today() - timedelta(days=days_stocked_out)

        else:
            if action_type == 'stockonhand':
                if self.current_stock != value:
                    reconciliation_transaction = mk_reconciliation(value - self.current_stock)
                self.current_stock = value
            elif action_type == 'receipts':
                self.current_stock += value
            elif action_type == 'consumption':
                self.current_stock -= value

            # data normalization
            if self.current_stock > 0:
                self.stocked_out_since = None
            else:
                self.current_stock = 0 # handle if negative
                if not self.stocked_out_since: # handle if stocked out date already set
                    self.stocked_out_since = date.today()

        return reconciliation_transaction

    def to_case_block(self, user_id=None):
        def convert_prop(val):
            return str(val) if val is not None else ''

        props = ['current_stock', 'stocked_out_since']

        case_update = CaseBlock(
            version=V2,
            case_id=self.case._id,
            user_id=user_id or 'FIXME',
            update=dict((k, convert_prop(getattr(self, k))) for k in props)
        ).as_xml()
        # convert xml.etree to lxml
        case_update = etree.fromstring(legacy_etree.ElementTree.tostring(case_update))

        return case_update


