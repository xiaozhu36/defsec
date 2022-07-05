package sqs

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aws/aws-sdk-go-v2/aws"
	sqsapi "github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/liamg/iamgo"
)

type adapter struct {
	*aws2.RootAdapter
	api *sqsapi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "sqs"
}

func (a *adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = sqsapi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.SQS.Queues, err = a.getQueues()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getQueues() (queues []sqs.Queue, err error) {

	a.Tracker().SetServiceLabel("Scanning queues...")

	batchQueues, token, err := a.getQueueBatch(nil)

	queues = append(queues, batchQueues...)

	for token != nil {
		batchQueues, token, err = a.getQueueBatch(token)
		queues = append(queues, batchQueues...)
	}

	return queues, nil
}

func (a *adapter) getQueueBatch(token *string) (queues []sqs.Queue, nextToken *string, err error) {

	input := &sqsapi.ListQueuesInput{}

	if token != nil {
		input.NextToken = token
	}

	apiQueues, err := a.api.ListQueues(a.Context(), input)
	if err != nil {
		return queues, nil, err
	}

	for _, queueUrl := range apiQueues.QueueUrls {

		queueMetadata := a.CreateMetadata(queueUrl)
		queueAttributes, err := a.api.GetQueueAttributes(a.Context(), &sqsapi.GetQueueAttributesInput{
			QueueUrl: aws.String(queueUrl),
			AttributeNames: []sqsTypes.QueueAttributeName{
				sqsTypes.QueueAttributeNameSqsManagedSseEnabled,
				sqsTypes.QueueAttributeNameKmsMasterKeyId,
				sqsTypes.QueueAttributeNamePolicy,
			},
		})
		if err != nil {
			return queues, nil, err
		}

		queue := sqs.NewQueue(queueMetadata)

		queue.QueueURL = types.String(queueUrl, queueMetadata)

		sseEncrypted := queueAttributes.Attributes[string(sqsTypes.QueueAttributeNameSqsManagedSseEnabled)]
		kmsEncryption := queueAttributes.Attributes[string(sqsTypes.QueueAttributeNameKmsMasterKeyId)]
		queuePolicy := queueAttributes.Attributes[string(sqsTypes.QueueAttributeNamePolicy)]

		if sseEncrypted == "SSE-SQS" {
			queue.Encryption.ManagedEncryption = types.Bool(true, queueMetadata)
		}

		if kmsEncryption != "" {
			queue.Encryption.KMSKeyID = types.String(kmsEncryption, queueMetadata)
		}

		if queuePolicy != "" {
			policy, err := iamgo.ParseString(queuePolicy)
			if err == nil {

				queue.Policies = append(queue.Policies, iam.Policy{
					Metadata: queueMetadata,
					Document: iam.Document{
						Metadata: queueMetadata,
						Parsed:   *policy,
					},
				})

			}

		}
		a.Tracker().IncrementResource()
		queues = append(queues, queue)
	}
	return queues, apiQueues.NextToken, nil

}
